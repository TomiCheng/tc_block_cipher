//! DES and Triple DES through the RustCrypto `des` crate.

use core::fmt;

use ::des::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use ::des::{Des, TdesEde2, TdesEde3};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::{BLOCK_BYTES, DES_ALGO_NAME, DES_EDE_ALGO_NAME, EDE2_KEY_BYTES, EDE3_KEY_BYTES};

/// Splits the first block off both buffers, or reports that one is too short.
/// Constant time: branches only on the public buffer lengths.
fn first_blocks<'a>(
    input: &'a [u8],
    output: &'a mut [u8],
) -> Result<(&'a Block<Des>, &'a mut Block<Des>), BlockError> {
    match (
        input
            .get(..BLOCK_BYTES)
            .and_then(Block::<Des>::slice_as_array),
        output
            .get_mut(..BLOCK_BYTES)
            .and_then(Block::<Des>::slice_as_mut_array),
    ) {
        (Some(input), Some(output)) => Ok((input, output)),
        _ => Err(BlockError::BufferTooShort),
    }
}

/// DES backed by RustCrypto's `des` crate, with an 8-byte encoded key and an
/// 8-byte block.
///
/// For legacy interoperability only; do not use in new designs.
/// Parity bits are ignored and weak keys are not rejected.
///
/// Variable time: rounds index 64-byte S-boxes with secret data. The tables
/// are smaller than [`DesTableEngine`](crate::DesTableEngine)'s SP-boxes, which narrows
/// the cache-timing channel without closing it; this crate provides no
/// constant-time alternative.
///
/// Stored schedules are wiped on replacement and drop by the `des` crate. This
/// does not wipe caller buffers or guarantee erasure of every register or
/// stack copy.
///
/// # Example
///
/// Requires the `rustcrypto` Cargo feature.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_des::{BLOCK_BYTES, DesRustCryptoEngine};
///
/// let key = [0x42; 8];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = DesRustCryptoEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// assert_eq!(engine.to_string(), "DES");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct DesRustCryptoEngine {
    cipher: Option<Des>,
    direction: CipherDirection,
}

impl DesRustCryptoEngine {
    /// Creates an uninitialised DES engine. Constant time.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl Default for DesRustCryptoEngine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DesRustCryptoEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(DES_ALGO_NAME)
    }
}

impl BlockCipher for DesRustCryptoEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Processes the first block and returns 8, preserving the output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: secret-dependent S-box lookups can leak key information.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let cipher = self.cipher.as_ref().ok_or(BlockError::NotInitialised)?;
        let (input, output) = first_blocks(input, output)?;
        match self.direction {
            CipherDirection::Encrypt => cipher.encrypt_block_b2b(input, output),
            CipherDirection::Decrypt => cipher.decrypt_block_b2b(input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for DesRustCryptoEngine {
    type Error = InitError;

    /// Installs an 8-byte encoded key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Parity bits are ignored and weak keys are accepted.
    /// Constant time: the key schedule uses fixed bit permutations and rotations,
    /// and branches only on the key length.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let cipher =
            Des::new_from_slice(key).map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        self.cipher = Some(cipher);
        self.direction = direction;
        Ok(())
    }
}

enum TripleDes {
    Ede2(TdesEde2),
    Ede3(TdesEde3),
}

/// EDE Triple DES backed by RustCrypto's `des` crate, with a 16-byte or
/// 24-byte encoded key and an 8-byte block.
///
/// For legacy interoperability only; do not use in new designs.
/// Parity bits are ignored and weak keys are not rejected. A 16-byte key is
/// used as `K1, K2, K1`.
///
/// Variable time: rounds index 64-byte S-boxes with secret data. The tables
/// are smaller than [`DesEdeTableEngine`](crate::DesEdeTableEngine)'s SP-boxes, which
/// narrows the cache-timing channel without closing it; this crate provides
/// no constant-time alternative.
///
/// Stored schedules are wiped on replacement and drop by the `des` crate. This
/// does not wipe caller buffers or guarantee erasure of every register or
/// stack copy.
///
/// # Example
///
/// Requires the `rustcrypto` Cargo feature.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_des::{BLOCK_BYTES, DesEdeRustCryptoEngine};
///
/// let key = [0x42; 24];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = DesEdeRustCryptoEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// assert_eq!(engine.to_string(), "DESede");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct DesEdeRustCryptoEngine {
    cipher: Option<TripleDes>,
    direction: CipherDirection,
}

impl DesEdeRustCryptoEngine {
    /// Creates an uninitialised Triple DES engine. Constant time.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl Default for DesEdeRustCryptoEngine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DesEdeRustCryptoEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(DES_EDE_ALGO_NAME)
    }
}

impl BlockCipher for DesEdeRustCryptoEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Processes the first block and returns 8, preserving the output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: secret-dependent S-box lookups can leak key information.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let cipher = self.cipher.as_ref().ok_or(BlockError::NotInitialised)?;
        let (input, output) = first_blocks(input, output)?;
        match (cipher, self.direction) {
            (TripleDes::Ede2(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (TripleDes::Ede2(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
            (TripleDes::Ede3(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (TripleDes::Ede3(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for DesEdeRustCryptoEngine {
    type Error = InitError;

    /// Installs a 16- or 24-byte encoded key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Parity bits are ignored and weak keys are accepted.
    /// Constant time: the key schedule uses fixed bit permutations and rotations,
    /// and branches only on the key length.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let invalid = |_| InitError::InvalidKeyLength(key.len());
        let cipher = match key.len() {
            EDE2_KEY_BYTES => TripleDes::Ede2(TdesEde2::new_from_slice(key).map_err(invalid)?),
            EDE3_KEY_BYTES => TripleDes::Ede3(TdesEde3::new_from_slice(key).map_err(invalid)?),
            len => return Err(InitError::InvalidKeyLength(len)),
        };
        self.cipher = Some(cipher);
        self.direction = direction;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};

    use super::{DesEdeRustCryptoEngine, DesRustCryptoEngine};
    use crate::{BLOCK_BYTES, DesEdeTableEngine, DesTableEngine};

    fn process<E>(mut engine: E, direction: CipherDirection, key: &[u8], input: &[u8; 8]) -> [u8; 8]
    where
        E: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
    {
        let mut output = [0; BLOCK_BYTES];
        assert!(engine.init(direction, &KeyRef::new(key)).is_ok());
        assert!(engine.process_block(input, &mut output).is_ok());
        output
    }

    fn check_vector<E>(new: fn() -> E, key: &[u8], plaintext: [u8; 8], ciphertext: [u8; 8])
    where
        E: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
    {
        assert_eq!(
            process(new(), CipherDirection::Encrypt, key, &plaintext),
            ciphertext
        );
        assert_eq!(
            process(new(), CipherDirection::Decrypt, key, &ciphertext),
            plaintext
        );
    }

    /// Compares an engine with the portable one on pseudorandom keys and
    /// blocks in both directions.
    fn check_agreement<A, B, const N: usize>(new_a: fn() -> A, new_b: fn() -> B)
    where
        A: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
        B: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
    {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for _ in 0..64 {
            let key: [u8; N] = core::array::from_fn(|_| next());
            let block: [u8; 8] = core::array::from_fn(|_| next());
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                assert_eq!(
                    process(new_a(), direction, &key, &block),
                    process(new_b(), direction, &key, &block),
                    "{N}-byte key, {direction:?}"
                );
            }
        }
    }

    #[test]
    fn des_matches_the_standard_vector_and_a_weak_key_vector() {
        check_vector(
            DesRustCryptoEngine::new,
            &[0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            [0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05],
        );
        check_vector(
            DesRustCryptoEngine::new,
            &[0x01; 8],
            [0x95, 0xf8, 0xa5, 0xe5, 0xdd, 0x31, 0xd9, 0x00],
            [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
    }

    #[test]
    fn triple_des_matches_the_two_key_and_three_key_vectors() {
        check_vector(
            DesEdeRustCryptoEngine::new,
            &[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ],
            *b"Now is t",
            [0xd8, 0x0a, 0x0d, 0x8b, 0x2b, 0xae, 0x5e, 0x4e],
        );
        check_vector(
            DesEdeRustCryptoEngine::new,
            &[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
                0xef, 0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
            ],
            [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
            [0x07, 0x37, 0xf6, 0xc5, 0x37, 0x50, 0xd4, 0xa4],
        );
    }

    #[test]
    fn the_rustcrypto_engines_agree_with_the_portable_engines() {
        check_agreement::<_, _, 8>(DesRustCryptoEngine::new, DesTableEngine::new);
        check_agreement::<_, _, 16>(DesEdeRustCryptoEngine::new, DesEdeTableEngine::new);
        check_agreement::<_, _, 24>(DesEdeRustCryptoEngine::new, DesEdeTableEngine::new);
    }
}
