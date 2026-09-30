use core::fmt;

use ::rc2::Rc2;
use ::rc2::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt};
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};

use crate::Rc2Params;
use crate::rc2::{ALGO_NAME, BLOCK_BYTES, MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES};

/// RC2 engine backed by RustCrypto's `rc2` crate, with the `rustcrypto`
/// feature.
///
/// It accepts the same parameters and reports the same errors as
/// [`Rc2TableEngine`](crate::Rc2TableEngine). Variable time for the same
/// reasons: key setup and every block index tables with secret data. The
/// expanded key is wiped when replaced and on drop.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_rc_cipher::{RC2_BLOCK_BYTES, Rc2RustCryptoEngine, Rc2ParamsRef};
///
/// let mut engine = Rc2RustCryptoEngine::new();
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
pub struct Rc2RustCryptoEngine {
    cipher: Option<Rc2>,
    direction: CipherDirection,
}

impl Rc2RustCryptoEngine {
    /// Creates an engine with no key installed. Constant time.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl Default for Rc2RustCryptoEngine {
    /// Same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc2RustCryptoEngine {
    /// Writes `"RC2"`. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl BlockCipher for Rc2RustCryptoEngine {
    type Error = BlockError;

    /// Returns 8, the block size in bytes. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Encrypts or decrypts one 8-byte block from `input` into `output` and
    /// returns 8.
    ///
    /// Returns `NotInitialised` before a successful `init`, or `BufferTooShort`
    /// when either buffer is shorter than 8 bytes; `output` is left untouched
    /// on error. Variable time: rc2 indexes the expanded key with block data.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let cipher = self.cipher.as_ref().ok_or(BlockError::NotInitialised)?;
        let input = input
            .get(..BLOCK_BYTES)
            .and_then(Block::<Rc2>::slice_as_array);
        let output = output
            .get_mut(..BLOCK_BYTES)
            .and_then(Block::<Rc2>::slice_as_mut_array);
        let (Some(input), Some(output)) = (input, output) else {
            return Err(BlockError::BufferTooShort);
        };
        match self.direction {
            CipherDirection::Encrypt => cipher.encrypt_block_b2b(input, output),
            CipherDirection::Decrypt => cipher.decrypt_block_b2b(input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: Rc2Params + ?Sized> BlockCipherInit<P> for Rc2RustCryptoEngine {
    type Error = InitError;

    /// Installs a 1- to 128-byte key with a 1- to 1024-bit effective size for
    /// `direction`.
    ///
    /// On error the previous key and direction stay in use. Variable time: key setup indexes the PI
    /// table with key bytes.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        // The rc2 crate panics on an empty key, a key longer than 128 bytes, or an
        // effective size of 0 or more than 1024 bits, so check with Rc2TableEngine's
        // rules first; a failed check keeps the previous state.
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let effective_key_bits = params.effective_key_bits();
        if effective_key_bits == 0 || effective_key_bits > MAX_EFFECTIVE_KEY_BITS {
            return Err(InitError::InvalidEffectiveKeyBits(effective_key_bits));
        }

        self.cipher = Some(Rc2::new_with_eff_key_len(key, effective_key_bits));
        self.direction = direction;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};

    use super::Rc2RustCryptoEngine;
    use crate::Rc2ParamsRef;
    use crate::rc2::{BLOCK_BYTES, MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES, Rc2TableEngine};

    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn process<E>(
        mut engine: E,
        direction: CipherDirection,
        key: &[u8],
        effective_key_bits: usize,
        input: &[u8],
    ) -> [u8; BLOCK_BYTES]
    where
        E: BlockCipher + for<'a> BlockCipherInit<Rc2ParamsRef<'a>>,
    {
        let params = Rc2ParamsRef::with_effective_key_bits(key, effective_key_bits);
        let mut output = [0; BLOCK_BYTES];
        assert!(engine.init(direction, &params).is_ok());
        assert!(engine.process_block(input, &mut output).is_ok());
        output
    }

    #[test]
    fn rc2_matches_the_rfc_2268_and_bouncy_castle_vectors_in_both_directions() {
        // Vectors from RFC 2268 and Bouncy Castle's RC2Test.cs.
        let vectors = [
            (
                "0000000000000000",
                63,
                "0000000000000000",
                "ebb773f993278eff",
            ),
            (
                "ffffffffffffffff",
                64,
                "ffffffffffffffff",
                "278b27e42e2f0d49",
            ),
            (
                "3000000000000000",
                64,
                "1000000000000001",
                "30649edf9be7d2c2",
            ),
            ("88", 64, "0000000000000000", "61a8a244adacccf0"),
            ("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"),
            (
                "88bca90e90875a7f0f79c384627bafb2",
                64,
                "0000000000000000",
                "1a807d272bbe5db1",
            ),
            (
                "88bca90e90875a7f0f79c384627bafb2",
                128,
                "0000000000000000",
                "2269552ab0f85ca6",
            ),
            (
                "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
                129,
                "0000000000000000",
                "5b78d3a43dfff1f1",
            ),
        ];
        for (key, bits, plaintext, ciphertext) in vectors {
            let (key, plaintext, ciphertext) = (unhex(key), unhex(plaintext), unhex(ciphertext));
            let new = Rc2RustCryptoEngine::new;
            assert_eq!(
                process(new(), CipherDirection::Encrypt, &key, bits, &plaintext),
                ciphertext[..]
            );
            assert_eq!(
                process(new(), CipherDirection::Decrypt, &key, bits, &ciphertext),
                plaintext[..]
            );
        }
    }

    #[test]
    fn the_rustcrypto_engine_agrees_with_the_portable_engine() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..256 {
            // Key lengths cover 1..=128 bytes and effective sizes 1..=1024 bits.
            let key_len = next() as usize % MAX_KEY_BYTES + 1;
            let bits = next() as usize % MAX_EFFECTIVE_KEY_BITS + 1;
            let key: Vec<u8> = (0..key_len).map(|_| next() as u8).collect();
            let block = next().to_le_bytes();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                assert_eq!(
                    process(Rc2RustCryptoEngine::new(), direction, &key, bits, &block),
                    process(Rc2TableEngine::new(), direction, &key, bits, &block),
                    "{key_len}-byte key, {bits} effective bits, {direction:?}"
                );
            }
        }
    }

    #[test]
    fn invalid_parameters_are_rejected_without_replacing_the_installed_key() {
        let key = [0x42; 16];
        let mut engine = Rc2RustCryptoEngine::new();
        let mut expected = [0; BLOCK_BYTES];
        let mut output = [0; BLOCK_BYTES];
        engine
            .init(CipherDirection::Encrypt, &Rc2ParamsRef::new(&key))
            .unwrap();
        engine.process_block(&[0x11; 8], &mut expected).unwrap();

        let long_key = [0; MAX_KEY_BYTES + 1];
        let rejected = [
            (Rc2ParamsRef::new(&[]), InitError::InvalidKeyLength(0)),
            (
                Rc2ParamsRef::new(&long_key),
                InitError::InvalidKeyLength(MAX_KEY_BYTES + 1),
            ),
            (
                Rc2ParamsRef::with_effective_key_bits(&key, 0),
                InitError::InvalidEffectiveKeyBits(0),
            ),
            (
                Rc2ParamsRef::with_effective_key_bits(&key, MAX_EFFECTIVE_KEY_BITS + 1),
                InitError::InvalidEffectiveKeyBits(MAX_EFFECTIVE_KEY_BITS + 1),
            ),
        ];
        for (params, error) in rejected {
            assert_eq!(engine.init(CipherDirection::Decrypt, &params), Err(error));
            engine.process_block(&[0x11; 8], &mut output).unwrap();
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn processing_reports_an_uninitialised_engine_and_short_buffers() {
        let mut engine = Rc2RustCryptoEngine::new();
        let mut output = [0; BLOCK_BYTES];
        assert_eq!(
            engine.process_block(&[0; 8], &mut output),
            Err(BlockError::NotInitialised)
        );

        engine
            .init(CipherDirection::Encrypt, &Rc2ParamsRef::new(&[0x42; 8]))
            .unwrap();
        assert_eq!(
            engine.process_block(&[0; 7], &mut output),
            Err(BlockError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0; 8], &mut output[..7]),
            Err(BlockError::BufferTooShort)
        );
        assert_eq!(engine.block_size(), BLOCK_BYTES);
        assert_eq!(std::format!("{engine}"), "RC2");
    }
}
