//! Feature-selected Blowfish engine and its backends.

mod cipher;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod table_engine;

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::ALGO_NAME;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::BlowfishRustCryptoEngine;
pub use table_engine::BlowfishTableEngine;

#[cfg(feature = "rustcrypto")]
use rustcrypto_engine::BlowfishRustCryptoEngine as Backend;
#[cfg(not(feature = "rustcrypto"))]
use table_engine::BlowfishTableEngine as Backend;

/// Blowfish with a 4- to 56-byte key and an 8-byte block, on the backend the
/// build selects: `BlowfishRustCryptoEngine` with the `rustcrypto` feature,
/// otherwise [`BlowfishTableEngine`](crate::BlowfishTableEngine).
///
/// Variable time: both backends index key-dependent S-boxes with secret data
/// during key setup and block processing. Use only where cache-timing leakage
/// is outside the threat model. Each backend wipes its stored key schedule on
/// replacement and drop; caller buffers and temporary copies are not wiped.
///
/// # Example
///
/// Import both traits and reinitialize the engine to change direction.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_blowfish::{BLOCK_BYTES, MIN_KEY_BYTES, BlowfishEngine};
///
/// let key = [0x42; MIN_KEY_BYTES];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = BlowfishEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct BlowfishEngine {
    inner: Backend,
}

impl BlowfishEngine {
    /// Creates an uninitialised engine on the selected backend. Constant time:
    /// no key is inspected.
    pub const fn new() -> Self {
        Self {
            inner: Backend::new(),
        }
    }
}

impl Default for BlowfishEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for BlowfishEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl BlockCipher for BlowfishEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    /// Transforms the first block through the selected backend, with the same
    /// errors and untouched-output guarantees as each backend.
    /// Variable time: secret-dependent S-box lookups can leak key information.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.inner.process_block(input, output)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for BlowfishEngine {
    type Error = InitError;

    /// Installs a 4- to 56-byte key on the selected backend; an invalid length
    /// leaves the previous state unchanged. Variable time: key expansion uses
    /// secret-dependent S-box lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}
