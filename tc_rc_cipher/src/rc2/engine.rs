use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};

use crate::Rc2Params;
use crate::rc2::ALGO_NAME;

#[cfg(feature = "rustcrypto")]
type Inner = crate::rc2::Rc2RustCryptoEngine;
#[cfg(not(feature = "rustcrypto"))]
type Inner = crate::rc2::Rc2TableEngine;

/// RC2 engine whose backend is chosen at build time.
///
/// With the `rustcrypto` feature it uses `Rc2RustCryptoEngine`; otherwise it
/// uses [`Rc2TableEngine`](crate::Rc2TableEngine). Both are variable time,
/// so use RC2 only where cache-timing attacks are out of scope.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_rc_cipher::{RC2_BLOCK_BYTES, Rc2Engine, Rc2ParamsRef};
///
/// let mut engine = Rc2Engine::new();
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
pub struct Rc2Engine {
    inner: Inner,
}

impl Rc2Engine {
    /// Creates an engine with no key installed. Constant time.
    pub const fn new() -> Self {
        Self {
            inner: Inner::new(),
        }
    }
}

impl Default for Rc2Engine {
    /// Same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc2Engine {
    /// Writes `"RC2"`. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl BlockCipher for Rc2Engine {
    type Error = BlockError;

    /// Returns 8, the block size in bytes. Constant time.
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    /// Encrypts or decrypts one 8-byte block from `input` into `output` and
    /// returns 8.
    ///
    /// Returns `NotInitialised` before a successful `init`, or `BufferTooShort`
    /// when either buffer is shorter than 8 bytes; `output` is left untouched
    /// on error. Variable time, as the backend is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.inner.process_block(input, output)
    }
}

impl<P: Rc2Params + ?Sized> BlockCipherInit<P> for Rc2Engine {
    type Error = InitError;

    /// Installs a 1- to 128-byte key with a 1- to 1024-bit effective size for
    /// `direction`.
    ///
    /// On error the previous key and direction stay in use. Variable time, as
    /// the backend is.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}
