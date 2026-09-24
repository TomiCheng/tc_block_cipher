//! DES and Triple DES on the engine the build selects.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::{DES_ALGO_NAME, DES_EDE_ALGO_NAME};

#[cfg(feature = "rustcrypto")]
type DesInner = crate::DesRustCryptoEngine;
#[cfg(not(feature = "rustcrypto"))]
type DesInner = crate::DesTableEngine;

#[cfg(feature = "rustcrypto")]
type DesEdeInner = crate::DesEdeRustCryptoEngine;
#[cfg(not(feature = "rustcrypto"))]
type DesEdeInner = crate::DesEdeTableEngine;

/// DES on the least leaky engine the build provides: `DesRustCryptoEngine`
/// when the `rustcrypto` feature is on, otherwise
/// [`DesTableEngine`](crate::DesTableEngine). The choice is made at compile
/// time; the type and its API are the same under every configuration.
///
/// For legacy interoperability only; do not use in new designs.
///
/// Variable time under either engine: both look up S-boxes with secret data.
/// The RustCrypto engine's smaller S-boxes and branch-free key schedule narrow
/// the cache-timing channel compared with the table engine, so enable
/// `rustcrypto` to get them; this crate provides no constant-time alternative.
///
/// # Example
///
/// Call `init` again to install a new key or change direction.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_des::{BLOCK_BYTES, DesEngine};
///
/// let key = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
/// let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
/// let mut engine = DesEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut ciphertext = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut ciphertext)?;
/// assert_eq!(ciphertext, [0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05]);
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// assert_eq!(engine.to_string(), "DES");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct DesEngine {
    inner: DesInner,
}

impl DesEngine {
    /// Creates an uninitialised engine on the selected backend. Constant time.
    pub const fn new() -> Self {
        Self {
            inner: DesInner::new(),
        }
    }
}

impl Default for DesEngine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DesEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(DES_ALGO_NAME)
    }
}

impl BlockCipher for DesEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    /// Processes the first block and returns 8, preserving the output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: both engines look up S-boxes with secret data.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.inner.process_block(input, output)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for DesEngine {
    type Error = InitError;

    /// Installs an 8-byte encoded key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Parity bits are ignored and weak keys are accepted.
    /// Variable time in the default build, where the table engine's key setup
    /// branches on key bits; the RustCrypto key schedule has no such branches.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}

/// EDE Triple DES on the least leaky engine the build provides:
/// `DesEdeRustCryptoEngine` when the `rustcrypto` feature is on, otherwise
/// [`DesEdeTableEngine`](crate::DesEdeTableEngine). The choice is made at
/// compile time; the type and its API are the same under every configuration.
///
/// For legacy interoperability only; do not use in new designs. A 16-byte key
/// is used as `K1, K2, K1`.
///
/// Variable time under either engine: both look up S-boxes with secret data.
/// The RustCrypto engine's smaller S-boxes and branch-free key schedule narrow
/// the cache-timing channel compared with the table engine, so enable
/// `rustcrypto` to get them; this crate provides no constant-time alternative.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_des::{BLOCK_BYTES, DesEdeEngine};
///
/// let key = [
///     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89,
///     0xab, 0xcd, 0xef, 0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
/// ];
/// let plaintext = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
/// let mut engine = DesEdeEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut ciphertext = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut ciphertext)?;
/// assert_eq!(ciphertext, [0x07, 0x37, 0xf6, 0xc5, 0x37, 0x50, 0xd4, 0xa4]);
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// assert_eq!(engine.to_string(), "DESede");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct DesEdeEngine {
    inner: DesEdeInner,
}

impl DesEdeEngine {
    /// Creates an uninitialised engine on the selected backend. Constant time.
    pub const fn new() -> Self {
        Self {
            inner: DesEdeInner::new(),
        }
    }
}

impl Default for DesEdeEngine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DesEdeEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(DES_EDE_ALGO_NAME)
    }
}

impl BlockCipher for DesEdeEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    /// Processes the first block and returns 8, preserving the output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: both engines look up S-boxes with secret data.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.inner.process_block(input, output)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for DesEdeEngine {
    type Error = InitError;

    /// Installs a 16- or 24-byte encoded key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Parity bits are ignored and weak keys are accepted.
    /// Variable time in the default build, where the table engine's key setup
    /// branches on key bits; the RustCrypto key schedule has no such branches.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.inner.init(direction, params)
    }
}
