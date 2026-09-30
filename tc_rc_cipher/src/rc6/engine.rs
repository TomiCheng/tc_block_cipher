use core::fmt;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::rc6::cipher::SUBKEYS;
use crate::rc6::{ALGO_NAME, BLOCK_BYTES, MAX_KEY_BYTES, cipher};

/// RC6-32/20 engine with a 16-byte block and a 1- to 255-byte key.
///
/// Constant time on processors with fixed-latency rotations and 32-bit
/// multiplication, such as mainstream x86, x86-64 and AArch64; processors
/// without a barrel shifter or with early-terminating multipliers can leak
/// secret data. The expanded key is wiped when replaced and on drop.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_cipher::KeyRef;
/// use tc_rc_cipher::{RC6_BLOCK_BYTES, Rc6Engine};
///
/// let mut engine = Rc6Engine::new();
/// let params = KeyRef::new(&[0x42; 16]);
/// let plaintext = [0x11; RC6_BLOCK_BYTES];
///
/// engine.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; RC6_BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut ciphertext)?;
///
/// engine.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; RC6_BLOCK_BYTES];
/// engine.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Rc6Engine {
    subkeys: [u32; SUBKEYS],
    direction: CipherDirection,
    initialised: bool,
}

impl Rc6Engine {
    /// Creates an engine with no key installed. Constant time.
    pub const fn new() -> Self {
        Self {
            subkeys: [0; SUBKEYS],
            direction: CipherDirection::Encrypt,
            initialised: false,
        }
    }
}

impl Default for Rc6Engine {
    /// Same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Rc6Engine {
    /// Writes `"RC6"`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for Rc6Engine {
    fn drop(&mut self) {
        self.subkeys.zeroize();
    }
}

impl BlockCipher for Rc6Engine {
    type Error = BlockError;

    /// Returns 16, the block size in bytes. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Encrypts or decrypts one 16-byte block from `input` into `output` and
    /// returns 16.
    ///
    /// Returns `NotInitialised` before a successful `init`, or `BufferTooShort`
    /// when either buffer is shorter than 16 bytes; `output` is left untouched
    /// on error. Constant time on processors with fixed-latency
    /// rotations and 32-bit multiplication, such as mainstream x86, x86-64 and
    /// AArch64.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        let (Some(input), Some(output)) = (
            input.first_chunk::<BLOCK_BYTES>(),
            output.first_chunk_mut::<BLOCK_BYTES>(),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        match self.direction {
            CipherDirection::Encrypt => cipher::encrypt(&self.subkeys, input, output),
            CipherDirection::Decrypt => cipher::decrypt(&self.subkeys, input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Rc6Engine {
    type Error = InitError;

    /// Installs a 1- to 255-byte key for `direction`.
    ///
    /// On error the previous key and direction stay in use. Constant time on
    /// processors with fixed-latency rotations and 32-bit multiplication, such as
    /// mainstream x86, x86-64 and AArch64.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        self.subkeys.zeroize();
        // Both directions use the same schedule, traversed in opposite orders.
        cipher::expand_key(key, &mut self.subkeys);
        self.direction = direction;
        self.initialised = true;
        Ok(())
    }
}
