//! Threefish after Bouncy Castle's `ThreefishEngine`.

use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_zeroize::Zeroize;

use crate::cipher::{self, C_240, threefish256, threefish512, threefish1024};
use crate::{
    THREEFISH_256_ALGO_NAME, THREEFISH_512_ALGO_NAME, THREEFISH_1024_ALGO_NAME, TWEAK_BYTES,
    ThreefishParams,
};

/// Portable Threefish after Bouncy Castle, with a compile-time block width.
///
/// `WORDS` must be 4, 8, or 16, selecting Threefish-256, Threefish-512, or
/// Threefish-1024. Each width runs its own round function, unrolled to eight
/// rounds per loop iteration. The subkey schedule is not expanded in advance:
/// `init` stores only the key, its parity word and the tweak, and each block
/// reads its subkeys from them. Rekeying is therefore cheap, which suits
/// callers that change the key or tweak for every block, as Skein does. In the
/// crate's benchmarks it was also faster per block than RustCrypto's engine.
///
/// Constant time with respect to key, tweak and block contents: additions,
/// XORs, rotations and schedule offsets follow the public round number.
///
/// Stored keys, parity and tweaks are wiped on replacement and drop. This
/// does not wipe caller buffers or guarantee erasure of every register or stack copy.
///
/// # Example
///
/// Bypasses the feature-selected [`ThreefishEngine`](crate::ThreefishEngine):
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_threefish::{ThreefishParamsRef, ThreefishPortableEngine};
///
/// let params = ThreefishParamsRef::with_tweak(&[0x42; 64], &[0x11; 16]);
/// let mut engine = ThreefishPortableEngine::<8>::new();
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
/// const INVALID: tc_threefish::ThreefishPortableEngine<3> =
///     tc_threefish::ThreefishPortableEngine::new();
/// ```
pub struct ThreefishPortableEngine<const WORDS: usize> {
    // `key || parity || key`, which is `2 * WORDS + 1` words; three rows hold
    // it because that length cannot be an array length of a generic type.
    kw: [[u64; WORDS]; 3],
    // `t0, t1, t0 ^ t1, t0, t1`.
    tweak: [u64; 5],
    direction: CipherDirection,
    initialised: bool,
}

impl<const WORDS: usize> ThreefishPortableEngine<WORDS> {
    const VALID_WORD_COUNT: () = assert!(
        cipher::valid_word_count(WORDS),
        "Threefish WORDS must be 4, 8, or 16"
    );

    /// Creates an uninitialised engine for the selected Threefish variant. Constant time.
    pub const fn new() -> Self {
        let () = Self::VALID_WORD_COUNT;
        Self {
            kw: [[0; WORDS]; 3],
            tweak: [0; 5],
            direction: CipherDirection::Encrypt,
            initialised: false,
        }
    }
}

impl<const WORDS: usize> Default for ThreefishPortableEngine<WORDS> {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<const WORDS: usize> fmt::Display for ThreefishPortableEngine<WORDS> {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match WORDS {
            4 => output.write_str(THREEFISH_256_ALGO_NAME),
            8 => output.write_str(THREEFISH_512_ALGO_NAME),
            16 => output.write_str(THREEFISH_1024_ALGO_NAME),
            _ => unreachable!("ThreefishPortableEngine validates WORDS"),
        }
    }
}

impl<const WORDS: usize> BlockCipher for ThreefishPortableEngine<WORDS> {
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
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }

        let block_bytes = self.block_size();
        if input.len() < block_bytes || output.len() < block_bytes {
            return Err(BlockError::BufferTooShort);
        }

        let mut words = [0u64; WORDS];
        for (word, bytes) in words.iter_mut().zip(input[..block_bytes].chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }

        let kw = &self.kw.as_flattened()[..2 * WORDS + 1];
        let t = &self.tweak;
        let block = words.as_mut_slice();
        match (WORDS, self.direction) {
            (4, CipherDirection::Encrypt) => threefish256::encrypt(kw, t, block),
            (4, CipherDirection::Decrypt) => threefish256::decrypt(kw, t, block),
            (8, CipherDirection::Encrypt) => threefish512::encrypt(kw, t, block),
            (8, CipherDirection::Decrypt) => threefish512::decrypt(kw, t, block),
            (16, CipherDirection::Encrypt) => threefish1024::encrypt(kw, t, block),
            (16, CipherDirection::Decrypt) => threefish1024::decrypt(kw, t, block),
            _ => unreachable!("ThreefishPortableEngine validates WORDS"),
        }

        for (word, bytes) in words.iter().zip(output[..block_bytes].chunks_exact_mut(8)) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        Ok(block_bytes)
    }
}

impl<P: ThreefishParams + ?Sized, const WORDS: usize> BlockCipherInit<P>
    for ThreefishPortableEngine<WORDS>
{
    type Error = InitError;

    /// Installs a block-sized key and an optional 16-byte tweak for the selected direction.
    ///
    /// An absent tweak means zero. Invalid key or tweak lengths preserve all prior state.
    /// Constant time with respect to key and tweak contents; lengths are public.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.len() != WORDS * 8 {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let tweak = params.tweak();
        if let Some(tweak) = tweak {
            if tweak.len() != TWEAK_BYTES {
                return Err(InitError::InvalidTweakLength(tweak.len()));
            }
        }

        self.kw.zeroize();
        self.tweak.zeroize();
        let kw = self.kw.as_flattened_mut();
        for (word, bytes) in kw[..WORDS].iter_mut().zip(key.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        kw[WORDS] = kw[..WORDS].iter().fold(C_240, |parity, word| parity ^ word);
        kw.copy_within(..WORDS, WORDS + 1);

        let mut tweak_words = [0u64; 2];
        if let Some(tweak) = tweak {
            for (word, bytes) in tweak_words.iter_mut().zip(tweak.chunks_exact(8)) {
                *word = u64::from_le_bytes(bytes.try_into().unwrap());
            }
        }
        let [t0, t1] = tweak_words;
        self.tweak = [t0, t1, t0 ^ t1, t0, t1];

        tweak_words.zeroize();
        self.direction = direction;
        self.initialised = true;
        Ok(())
    }
}

impl<const WORDS: usize> Drop for ThreefishPortableEngine<WORDS> {
    fn drop(&mut self) {
        self.kw.zeroize();
        self.tweak.zeroize();
    }
}
