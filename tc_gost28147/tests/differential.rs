//! GOST 28147 agrees with RustCrypto's `magma` under the CryptoPro A, B and C
//! S-boxes.
//!
//! `magma` reads keys and blocks big-endian as GOST R 34.12-2015 does, while
//! Bouncy Castle and this crate read them little-endian, so each key word and
//! each whole block is byte-reversed on the way to and from `magma`.
//!
//! `magma` 0.10's `CryptoProD` table differs from the CryptoPro-D parameter
//! set of RFC 4357, which `s_box::E_D` and Bouncy Castle match, and its
//! `TestSbox` is not Bouncy Castle's `E-Test`, so neither is compared here.
//! `tests/rfc4357_tables.rs` checks the tables against the RFC instead.

use magma::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use magma::{Gost89CryptoProA, Gost89CryptoProB, Gost89CryptoProC};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_gost28147::{BLOCK_BYTES, Gost28147Engine, Gost28147ParamsRef, KEY_BYTES, s_box};

macro_rules! compare {
    ($name:ident, $reference:ty, $table:expr) => {
        #[test]
        fn $name() {
            let mut seed = 0x9e37_79b9_7f4a_7c15u64;
            let mut next = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            };
            for _ in 0..64 {
                let key: [u8; KEY_BYTES] = core::array::from_fn(|_| next());
                let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());

                let mut reference_key = key;
                for word in reference_key.chunks_exact_mut(4) {
                    word.reverse();
                }
                let reference = <$reference>::new_from_slice(&reference_key).unwrap();

                for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                    let mut reversed = input;
                    reversed.reverse();
                    let mut block = Block::<$reference>::from(reversed);
                    match direction {
                        CipherDirection::Encrypt => reference.encrypt_block(&mut block),
                        CipherDirection::Decrypt => reference.decrypt_block(&mut block),
                    }
                    let mut expected: [u8; BLOCK_BYTES] = block.into();
                    expected.reverse();

                    let mut engine = Gost28147Engine::new();
                    engine
                        .init(direction, &Gost28147ParamsRef::with_s_box(&key, &$table))
                        .unwrap();
                    let mut actual = [0; BLOCK_BYTES];
                    engine.process_block(&input, &mut actual).unwrap();
                    assert_eq!(actual, expected);
                }
            }
        }
    };
}

compare!(
    the_e_a_table_matches_rustcrypto_cryptopro_a_for_64_random_keys_and_blocks,
    Gost89CryptoProA,
    s_box::E_A
);

compare!(
    the_e_b_table_matches_rustcrypto_cryptopro_b_for_64_random_keys_and_blocks,
    Gost89CryptoProB,
    s_box::E_B
);

compare!(
    the_e_c_table_matches_rustcrypto_cryptopro_c_for_64_random_keys_and_blocks,
    Gost89CryptoProC,
    s_box::E_C
);
