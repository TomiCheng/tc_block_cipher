//! Blowfish through the RustCrypto `blowfish` crate.

use core::fmt;

use blowfish::Blowfish;
use blowfish::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::{ALGO_NAME, BLOCK_BYTES, MAX_KEY_BYTES, MIN_KEY_BYTES};

/// Blowfish backed by RustCrypto's `blowfish` crate, enabled with `rustcrypto`.
///
/// Variable time: the backend indexes key-dependent S-boxes with secret data
/// during key setup and block processing, like
/// [`BlowfishTableEngine`](crate::BlowfishTableEngine); it is not a
/// constant-time alternative. The stored key schedule is wiped on replacement
/// and drop through the backend's `zeroize` support; caller buffers and other
/// copies remain the caller's.
///
/// # Example
///
/// Requires the `rustcrypto` Cargo feature; bypasses the automatic dispatcher.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_blowfish::{BLOCK_BYTES, BlowfishRustCryptoEngine};
///
/// let mut engine = BlowfishRustCryptoEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&[0; 8]))?;
/// let mut output = [0; BLOCK_BYTES];
/// assert_eq!(engine.process_block(&[0; BLOCK_BYTES], &mut output)?, BLOCK_BYTES);
/// assert_eq!(output, [0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78]);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct BlowfishRustCryptoEngine {
    cipher: Option<Blowfish>,
    direction: CipherDirection,
}

impl BlowfishRustCryptoEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl Default for BlowfishRustCryptoEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for BlowfishRustCryptoEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl BlockCipher for BlowfishRustCryptoEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first block and returns 8, leaving any output tail untouched.
    ///
    /// Returns `NotInitialised` before successful initialization, or
    /// `BufferTooShort` when either buffer is shorter than 8 bytes.
    /// Both errors leave output untouched.
    /// Variable time: secret-dependent S-box lookups can leak key information.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let cipher = self.cipher.as_ref().ok_or(BlockError::NotInitialised)?;
        let (Some(input), Some(output)) = (
            input
                .get(..BLOCK_BYTES)
                .and_then(Block::<Blowfish>::slice_as_array),
            output
                .get_mut(..BLOCK_BYTES)
                .and_then(Block::<Blowfish>::slice_as_mut_array),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        match self.direction {
            CipherDirection::Encrypt => cipher.encrypt_block_b2b(input, output),
            CipherDirection::Decrypt => cipher.decrypt_block_b2b(input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for BlowfishRustCryptoEngine {
    type Error = InitError;

    /// Installs a 4- to 56-byte key for the selected direction, without borrowing it.
    ///
    /// An invalid length leaves the previous key, direction and initialization
    /// state unchanged; a valid one replaces the previous schedule, which the
    /// backend wipes as it drops. Variable time: key expansion uses
    /// secret-dependent S-box lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let cipher =
            Blowfish::new_from_slice(key).map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        self.cipher = Some(cipher);
        self.direction = direction;
        Ok(())
    }
}
