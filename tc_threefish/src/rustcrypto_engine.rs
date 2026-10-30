//! Threefish through the RustCrypto `threefish` crate.

use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_zeroize::Zeroize;
use threefish::{Threefish256, Threefish512, Threefish1024};

use crate::cipher;
use crate::{
    THREEFISH_256_ALGO_NAME, THREEFISH_512_ALGO_NAME, THREEFISH_1024_ALGO_NAME, TWEAK_BYTES,
    ThreefishParams,
};

#[expect(
    clippy::large_enum_variant,
    reason = "a const generic cannot name the backend type; the engine docs disclose the size"
)]
enum Cipher {
    Threefish256(Threefish256),
    Threefish512(Threefish512),
    Threefish1024(Threefish1024),
}

/// Threefish backed by RustCrypto's `threefish` crate, enabled with `rustcrypto`.
///
/// `WORDS` must be 4, 8, or 16, selecting Threefish-256, Threefish-512, or
/// Threefish-1024. `init` expands the whole subkey schedule. In the crate's
/// benchmarks this made `init` 5 to 10 times slower than on
/// [`ThreefishPortableEngine`](crate::ThreefishPortableEngine), and blocks
/// were not faster in exchange: they took up to twice as long. The stored
/// schedule takes the space of the Threefish-1024 one, 2688 bytes, whatever
/// the width.
///
/// Constant time with respect to key, tweak and block contents: the backend
/// uses only additions, XORs and rotations, and its schedule indices follow
/// the public round number.
///
/// The stored schedule is wiped on replacement and drop through the backend's
/// `zeroize` support. This does not wipe caller buffers or guarantee erasure
/// of every register or stack copy.
///
/// # Example
///
/// Requires the `rustcrypto` Cargo feature; bypasses the feature-selected
/// [`ThreefishEngine`](crate::ThreefishEngine):
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_threefish::{ThreefishParamsRef, ThreefishRustCryptoEngine};
///
/// let params = ThreefishParamsRef::with_tweak(&[0x42; 64], &[0x11; 16]);
/// let mut engine = ThreefishRustCryptoEngine::<8>::new();
/// engine.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 64];
/// assert_eq!(engine.process_block(&[0x22; 64], &mut ciphertext)?, 64);
/// assert_eq!(engine.to_string(), "Threefish-512");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// Unsupported block widths are rejected at compile time:
///
/// ```compile_fail
/// const INVALID: tc_threefish::ThreefishRustCryptoEngine<3> =
///     tc_threefish::ThreefishRustCryptoEngine::new();
/// ```
pub struct ThreefishRustCryptoEngine<const WORDS: usize> {
    cipher: Option<Cipher>,
    direction: CipherDirection,
}

impl<const WORDS: usize> ThreefishRustCryptoEngine<WORDS> {
    const VALID_WORD_COUNT: () = assert!(
        cipher::valid_word_count(WORDS),
        "Threefish WORDS must be 4, 8, or 16"
    );

    /// Creates an uninitialised engine for the selected Threefish variant. Constant time.
    pub const fn new() -> Self {
        let () = Self::VALID_WORD_COUNT;
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl<const WORDS: usize> Default for ThreefishRustCryptoEngine<WORDS> {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<const WORDS: usize> fmt::Display for ThreefishRustCryptoEngine<WORDS> {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match WORDS {
            4 => output.write_str(THREEFISH_256_ALGO_NAME),
            8 => output.write_str(THREEFISH_512_ALGO_NAME),
            16 => output.write_str(THREEFISH_1024_ALGO_NAME),
            _ => unreachable!("ThreefishRustCryptoEngine validates WORDS"),
        }
    }
}

impl<const WORDS: usize> BlockCipher for ThreefishRustCryptoEngine<WORDS> {
    type Error = BlockError;

    /// Returns the selected block length in bytes. Constant time.
    fn block_size(&self) -> usize {
        WORDS * 8
    }

    /// Processes one block and returns its length, preserving any output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Constant time with respect to key, tweak and block contents.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let cipher = self.cipher.as_ref().ok_or(BlockError::NotInitialised)?;

        let block_bytes = self.block_size();
        if input.len() < block_bytes || output.len() < block_bytes {
            return Err(BlockError::BufferTooShort);
        }

        let mut words = [0u64; WORDS];
        for (word, bytes) in words.iter_mut().zip(input[..block_bytes].chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }

        let block = words.as_mut_slice();
        match (cipher, self.direction) {
            (Cipher::Threefish256(c), CipherDirection::Encrypt) => {
                c.encrypt_block_u64(block.try_into().unwrap())
            }
            (Cipher::Threefish256(c), CipherDirection::Decrypt) => {
                c.decrypt_block_u64(block.try_into().unwrap())
            }
            (Cipher::Threefish512(c), CipherDirection::Encrypt) => {
                c.encrypt_block_u64(block.try_into().unwrap())
            }
            (Cipher::Threefish512(c), CipherDirection::Decrypt) => {
                c.decrypt_block_u64(block.try_into().unwrap())
            }
            (Cipher::Threefish1024(c), CipherDirection::Encrypt) => {
                c.encrypt_block_u64(block.try_into().unwrap())
            }
            (Cipher::Threefish1024(c), CipherDirection::Decrypt) => {
                c.decrypt_block_u64(block.try_into().unwrap())
            }
        }

        for (word, bytes) in words.iter().zip(output[..block_bytes].chunks_exact_mut(8)) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        Ok(block_bytes)
    }
}

impl<P: ThreefishParams + ?Sized, const WORDS: usize> BlockCipherInit<P>
    for ThreefishRustCryptoEngine<WORDS>
{
    type Error = InitError;

    /// Expands a block-sized key and an optional 16-byte tweak for the selected direction.
    ///
    /// An absent tweak means zero. Invalid key or tweak lengths preserve all prior state.
    /// Constant time with respect to key and tweak contents; lengths are public.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.len() != WORDS * 8 {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let mut tweak = [0u8; TWEAK_BYTES];
        if let Some(bytes) = params.tweak() {
            if bytes.len() != TWEAK_BYTES {
                return Err(InitError::InvalidTweakLength(bytes.len()));
            }
            tweak.copy_from_slice(bytes);
        }

        self.cipher = Some(match WORDS {
            4 => Cipher::Threefish256(Threefish256::new_with_tweak(
                key.try_into().unwrap(),
                &tweak,
            )),
            8 => Cipher::Threefish512(Threefish512::new_with_tweak(
                key.try_into().unwrap(),
                &tweak,
            )),
            16 => Cipher::Threefish1024(Threefish1024::new_with_tweak(
                key.try_into().unwrap(),
                &tweak,
            )),
            _ => unreachable!("ThreefishRustCryptoEngine validates WORDS"),
        });
        tweak.zeroize();
        self.direction = direction;
        Ok(())
    }
}
