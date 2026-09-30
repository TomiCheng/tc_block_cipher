use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_zeroize::Zeroize;

use crate::Rc2Params;
use crate::rc2::cipher::{self, SUBKEYS};
use crate::rc2::{ALGO_NAME, BLOCK_BYTES, MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES};

/// Portable RC2 engine.
///
/// Variable time: key setup indexes the PI table with key bytes, and every
/// block indexes the expanded key with block data. Use RC2 only where
/// cache-timing attacks are out of scope. The expanded key is wiped when
/// replaced and on drop.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_rc_cipher::{RC2_BLOCK_BYTES, Rc2TableEngine, Rc2ParamsRef};
///
/// let mut engine = Rc2TableEngine::new();
/// let params = Rc2ParamsRef::with_effective_key_bits(&[0x42; 16], 64);
/// let plaintext = [0x11; RC2_BLOCK_BYTES];
///
/// engine.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; RC2_BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut ciphertext)?;
///
/// engine.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; RC2_BLOCK_BYTES];
/// engine.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Rc2TableEngine {
    working_key: [u16; SUBKEYS],
    direction: CipherDirection,
    initialised: bool,
}

impl Rc2TableEngine {
    /// Creates an uninitialised RC2 engine. Constant time.
    pub const fn new() -> Self {
        Self {
            working_key: [0; SUBKEYS],
            direction: CipherDirection::Encrypt,
            initialised: false,
        }
    }
}

impl Default for Rc2TableEngine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc2TableEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for Rc2TableEngine {
    fn drop(&mut self) {
        self.working_key.zeroize();
    }
}

impl BlockCipher for Rc2TableEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Processes one block and returns 8, preserving the output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: mash rounds index subkeys with secret block data.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockError::BufferTooShort);
        }

        let input: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; BLOCK_BYTES] = (&mut output[..BLOCK_BYTES]).try_into().unwrap();
        match self.direction {
            CipherDirection::Encrypt => cipher::encrypt(&self.working_key, input, output),
            CipherDirection::Decrypt => cipher::decrypt(&self.working_key, input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: Rc2Params + ?Sized> BlockCipherInit<P> for Rc2TableEngine {
    type Error = InitError;

    /// Installs a 1- to 128-byte key with an effective size of 1 to 1024 bits.
    ///
    /// Invalid parameters preserve the previous key, direction and initialization state.
    /// Variable time: key setup indexes the PI table with secret data.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let effective_key_bits = params.effective_key_bits();
        if effective_key_bits == 0 || effective_key_bits > MAX_EFFECTIVE_KEY_BITS {
            return Err(InitError::InvalidEffectiveKeyBits(effective_key_bits));
        }

        self.working_key.zeroize();
        let mut expanded = cipher::expand_key(key, effective_key_bits);
        self.working_key.copy_from_slice(&expanded);
        expanded.zeroize();
        self.direction = direction;
        self.initialised = true;
        Ok(())
    }
}
