//! Feature-selected Camellia engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::ALGO_NAME;
#[cfg(feature = "rustcrypto")]
use crate::CamelliaRustCryptoEngine as Backend;
#[cfg(not(feature = "rustcrypto"))]
use crate::CamelliaTableEngine as Backend;

/// Camellia with RustCrypto when the `rustcrypto` feature is enabled, otherwise
/// the portable table engine.
///
/// Every backend uses secret-dependent table lookups. Selecting RustCrypto
/// does not make this engine constant time. The API is the same in either case.
///
/// `CamelliaLightEngine` touches fewer cache lines but also looks up tables
/// with secret data, so the dispatcher favours throughput and does not select
/// it. Use the light engine directly where a smaller cache footprint matters
/// more.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_camellia::{BLOCK_BYTES, CamelliaEngine};
///
/// let mut engine = CamelliaEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&[0x42; 16]))?;
/// let mut output = [0; BLOCK_BYTES];
/// engine.process_block(&[0; BLOCK_BYTES], &mut output)?;
/// assert_eq!(engine.to_string(), "Camellia");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct CamelliaEngine {
    inner: Backend,
}

impl CamelliaEngine {
    /// Creates an engine without a key. Initialize it before processing blocks.
    /// Constant time: the backend is selected at compile time.
    pub const fn new() -> Self {
        Self {
            inner: Backend::new(),
        }
    }
}

impl Default for CamelliaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CamelliaEngine {
    /// Writes the algorithm name without inspecting the key.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for CamelliaEngine {
    type Error = InitError;

    /// Installs a key and direction; an invalid key length preserves prior state.
    /// Variable time: the selected backend uses secret-dependent table lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}

impl BlockCipher for CamelliaEngine {
    type Error = BlockError;

    /// Returns the block size in bytes. Constant time.
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    /// Processes the first block, leaving any output tail unchanged.
    /// Returns `NotInitialised` or `BufferTooShort` without modifying output.
    /// Variable time: the selected backend uses secret-dependent table lookups.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.inner.process_block(input, output)
    }
}
