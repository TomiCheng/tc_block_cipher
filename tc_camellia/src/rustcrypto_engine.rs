//! Camellia through the RustCrypto `camellia` crate.

use camellia::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use camellia::{Camellia128, Camellia192, Camellia256};

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::BLOCK_BYTES;

type Block = camellia::cipher::Block<Camellia128>;

enum Cipher {
    Camellia128(Camellia128),
    Camellia192(Camellia192),
    Camellia256(Camellia256),
}

/// Camellia backed by RustCrypto's `camellia` crate, enabled with `rustcrypto`.
///
/// **Variable time:** the backend uses secret-dependent S-box lookups during
/// key setup and block processing. It is not a constant-time alternative to
/// `CamelliaTableEngine`. Stored keys are wiped on drop through the enabled
/// `zeroize` support; caller buffers and other copies remain the caller's.
///
/// # Example
///
/// Requires the `rustcrypto` Cargo feature; bypasses the automatic dispatcher.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_camellia::CamelliaRustCryptoEngine;
///
/// let mut engine = CamelliaRustCryptoEngine::new();
/// let key = [0x42; 32];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut output = [0; 16];
/// assert_eq!(engine.process_block(&[0; 16], &mut output)?, 16);
/// assert_eq!(engine.to_string(), "Camellia");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct CamelliaRustCryptoEngine {
    cipher: Option<Cipher>,
    direction: CipherDirection,
}

impl core::fmt::Display for CamelliaRustCryptoEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

impl CamelliaRustCryptoEngine {
    /// An engine without a key; `init` must come before `process_block`.
    /// Constant time.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl Default for CamelliaRustCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for CamelliaRustCryptoEngine {
    type Error = InitError;

    /// Expands a 16-, 24- or 32-byte key. Invalid lengths preserve prior state.
    /// Variable time: the backend uses secret-dependent S-box lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let invalid = |_| InitError::InvalidKeyLength(key.len());
        let cipher = match key.len() {
            16 => Cipher::Camellia128(Camellia128::new_from_slice(key).map_err(invalid)?),
            24 => Cipher::Camellia192(Camellia192::new_from_slice(key).map_err(invalid)?),
            32 => Cipher::Camellia256(Camellia256::new_from_slice(key).map_err(invalid)?),
            len => return Err(InitError::InvalidKeyLength(len)),
        };
        self.cipher = Some(cipher);
        self.direction = direction;
        Ok(())
    }
}

impl BlockCipher for CamelliaRustCryptoEngine {
    type Error = BlockError;

    /// Always 16. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first input block, leaving the output tail unchanged.
    /// Returns `NotInitialised` or `BufferTooShort` without modifying output.
    /// Variable time: the backend uses secret-dependent S-box lookups.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let cipher = self.cipher.as_ref().ok_or(BlockError::NotInitialised)?;
        let (Some(input), Some(output)) = (
            input.get(..BLOCK_BYTES).and_then(Block::slice_as_array),
            output
                .get_mut(..BLOCK_BYTES)
                .and_then(Block::slice_as_mut_array),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        match (cipher, self.direction) {
            (Cipher::Camellia128(c), CipherDirection::Encrypt) => {
                c.encrypt_block_b2b(input, output)
            }
            (Cipher::Camellia128(c), CipherDirection::Decrypt) => {
                c.decrypt_block_b2b(input, output)
            }
            (Cipher::Camellia192(c), CipherDirection::Encrypt) => {
                c.encrypt_block_b2b(input, output)
            }
            (Cipher::Camellia192(c), CipherDirection::Decrypt) => {
                c.decrypt_block_b2b(input, output)
            }
            (Cipher::Camellia256(c), CipherDirection::Encrypt) => {
                c.encrypt_block_b2b(input, output)
            }
            (Cipher::Camellia256(c), CipherDirection::Decrypt) => {
                c.decrypt_block_b2b(input, output)
            }
        }
        Ok(BLOCK_BYTES)
    }
}
