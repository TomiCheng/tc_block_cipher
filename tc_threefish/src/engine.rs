//! Feature-selected Threefish engine.

use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};

use crate::ThreefishParams;
#[cfg(not(feature = "rustcrypto"))]
use crate::ThreefishPortableEngine as Backend;
#[cfg(feature = "rustcrypto")]
use crate::ThreefishRustCryptoEngine as Backend;

/// Threefish with RustCrypto when the `rustcrypto` feature is enabled,
/// otherwise the portable engine, with a compile-time block width.
///
/// `WORDS` must be 4, 8, or 16, selecting Threefish-256, Threefish-512, or
/// Threefish-1024. The named aliases are usually more convenient.
///
/// Constant time with respect to key, tweak and block contents on either
/// backend. The API is the same in either case.
///
/// RustCrypto expands the whole subkey schedule in `init`, which pays off
/// when many blocks share a key and tweak. Callers that change them for every
/// block, as Skein does, should use
/// [`ThreefishPortableEngine`](crate::ThreefishPortableEngine) directly.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_threefish::{ThreefishParamsRef, Threefish256Engine};
///
/// let key = [0x42; 32];
/// let tweak = [0x11; 16];
/// let plaintext = [0x22; 32];
/// let params = ThreefishParamsRef::with_tweak(&key, &tweak);
/// let mut engine = Threefish256Engine::new();
/// engine.init(CipherDirection::Encrypt, &params)?;
/// let mut encrypted = [0; 32];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 32];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// Unsupported block widths are rejected at compile time:
///
/// ```compile_fail
/// const INVALID: tc_threefish::ThreefishEngine<3> = tc_threefish::ThreefishEngine::new();
/// ```
pub struct ThreefishEngine<const WORDS: usize> {
    inner: Backend<WORDS>,
}

impl<const WORDS: usize> ThreefishEngine<WORDS> {
    /// Creates an uninitialised engine for the selected Threefish variant.
    /// Constant time: the backend is selected at compile time.
    pub const fn new() -> Self {
        Self {
            inner: Backend::new(),
        }
    }
}

impl<const WORDS: usize> Default for ThreefishEngine<WORDS> {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<const WORDS: usize> fmt::Display for ThreefishEngine<WORDS> {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(output)
    }
}

impl<const WORDS: usize> BlockCipher for ThreefishEngine<WORDS> {
    type Error = BlockError;

    /// Returns the selected block length in bytes. Constant time.
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    /// Processes one block and returns its length, preserving any output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Constant time with respect to key, tweak and block contents.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.inner.process_block(input, output)
    }
}

impl<P: ThreefishParams + ?Sized, const WORDS: usize> BlockCipherInit<P>
    for ThreefishEngine<WORDS>
{
    type Error = InitError;

    /// Installs a block-sized key and an optional 16-byte tweak for the selected direction.
    ///
    /// An absent tweak means zero. Invalid key or tweak lengths preserve all prior state.
    /// Constant time with respect to key and tweak contents; lengths are public.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}

/// Threefish-256 engine with a 32-byte block and key.
pub type Threefish256Engine = ThreefishEngine<4>;
/// Threefish-512 engine with a 64-byte block and key.
pub type Threefish512Engine = ThreefishEngine<8>;
/// Threefish-1024 engine with a 128-byte block and key.
pub type Threefish1024Engine = ThreefishEngine<16>;
