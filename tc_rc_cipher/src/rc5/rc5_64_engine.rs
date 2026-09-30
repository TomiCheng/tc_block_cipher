//! RC5-64 block-cipher engine.

use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_zeroize::Zeroize;

use crate::Rc5Params;
use crate::rc5::cipher::Core;
use crate::rc5::{MAX_KEY_BYTES, MAX_ROUNDS, RC5_64_ALGO_NAME, RC5_64_BLOCK_BYTES};

/// RC5-64 engine with a 16-byte block.
///
/// It takes a 1- to 255-byte key and 0 to 255 rounds from
/// [`Rc5Params`](Rc5Params); [`Rc5ParamsRef`](crate::Rc5ParamsRef) is the
/// ready-made implementation.
///
/// Constant time on processors with operand-independent rotations, such as
/// mainstream x86, x86-64 and AArch64; other processors can leak through
/// data-dependent rotation counts. The expanded key is wiped when replaced and
/// on drop.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_rc_cipher::{RC5_64_BLOCK_BYTES, Rc564Engine, Rc5ParamsRef};
///
/// let mut engine = Rc564Engine::new();
/// let params = Rc5ParamsRef::with_default_rounds(&[0x42; 16]);
/// let plaintext = [0x11; RC5_64_BLOCK_BYTES];
///
/// engine.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; RC5_64_BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut ciphertext)?;
///
/// engine.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; RC5_64_BLOCK_BYTES];
/// engine.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Rc564Engine {
    core: Core<u64>,
    direction: CipherDirection,
    initialised: bool,
}

impl Rc564Engine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            core: Core::new(),
            direction: CipherDirection::Encrypt,
            initialised: false,
        }
    }
}

impl Default for Rc564Engine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc564Engine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(RC5_64_ALGO_NAME)
    }
}

impl Drop for Rc564Engine {
    fn drop(&mut self) {
        self.core.zeroize();
    }
}

impl BlockCipher for Rc564Engine {
    type Error = BlockError;

    /// Returns 16, the block size in bytes. Constant time.
    fn block_size(&self) -> usize {
        RC5_64_BLOCK_BYTES
    }

    /// Encrypts or decrypts one 16-byte block from `input` into `output` and
    /// returns 16.
    ///
    /// Returns `NotInitialised` before a successful `init`, or `BufferTooShort`
    /// when either buffer is shorter than 16 bytes; `output` is left untouched
    /// on error. Constant time on processors with operand-independent
    /// rotations, such as mainstream x86, x86-64 and AArch64.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        let (Some(input), Some(output)) = (
            input.first_chunk::<RC5_64_BLOCK_BYTES>(),
            output.first_chunk_mut::<RC5_64_BLOCK_BYTES>(),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        match self.direction {
            CipherDirection::Encrypt => self.core.encrypt(input, output),
            CipherDirection::Decrypt => self.core.decrypt(input, output),
        }
        Ok(RC5_64_BLOCK_BYTES)
    }
}

impl<P: Rc5Params + ?Sized> BlockCipherInit<P> for Rc564Engine {
    type Error = InitError;

    /// Installs a 1- to 255-byte key and 0 to 255 rounds for `direction`.
    ///
    /// On error the previous key and direction stay in use. Constant time on processors with
    /// operand-independent rotations, such as mainstream x86, x86-64 and AArch64.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let rounds = params.rounds();
        if rounds > MAX_ROUNDS {
            return Err(InitError::InvalidRounds(rounds));
        }
        self.core.expand_key(key, rounds);
        self.direction = direction;
        self.initialised = true;
        Ok(())
    }
}
