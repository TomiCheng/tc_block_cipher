//! OpenPGP CFB: vectors from Bouncy Castle's `OpenPgpCfbBlockCipher` for AES
//! and GOST 28147, plus the relation to plain CFB, direction, IV, reset and
//! errors.
//!
//! Bouncy Castle's tests exercise this mode only inside OpenPGP messages, so
//! the vectors were produced by running its `OpenPgpCfbBlockCipher` on the
//! inputs below.

mod common;

use common::{assert_only_the_first_segment_is_written, assert_vectors, process, unhex};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, InitError, KeyParams};
use tc_block_modes::{
    BlockCipherMode, BlockModeError, BlockModeInitError, FixedCfbBlockCipher,
    FixedOpenPgpCfbBlockCipher, IvParams, KeyWithIvRef,
};
use tc_gost28147::{Gost28147Engine, Gost28147Params, s_box};

const KEY: &str = "000102030405060708090a0b0c0d0e0f";
const PLAINTEXT: &str = concat!(
    "000102030405060708090a0b0c0d0e0f",
    "101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f",
    "303132333435363738393a3b3c3d3e3f",
);

type FixedAesOpenPgpCfb = FixedOpenPgpCfbBlockCipher<AesEngine, 16>;

fn fixed() -> FixedAesOpenPgpCfb {
    FixedAesOpenPgpCfb::new(AesEngine::new())
}

fn assert_aes_vectors(iv: &[u8], ciphertext: &str) {
    let key = unhex(KEY);
    let params = KeyWithIvRef::new(&key, iv);
    let (plaintext, ciphertext) = (unhex(PLAINTEXT), unhex(ciphertext));
    assert_vectors(&mut fixed(), &params, &plaintext, &ciphertext);
    #[cfg(feature = "alloc")]
    assert_vectors(
        &mut tc_block_modes::OpenPgpCfbBlockCipher::new(AesEngine::new()),
        &params,
        &plaintext,
        &ciphertext,
    );
}

#[test]
fn openpgp_cfb_matches_bouncy_castle_for_aes_with_the_zero_iv_openpgp_uses() {
    assert_aes_vectors(
        &[],
        concat!(
            "c6a03934838a5d8567468b69adc5d676",
            "a59b6214586273366f14c5ba4fd7b4f3",
            "aac96e3ece517e590c11d41154ca3f74",
            "46c67e57a75188a9a1b186e0e57590db",
        ),
    );
}

#[test]
fn openpgp_cfb_matches_bouncy_castle_for_aes_with_a_nonzero_iv() {
    assert_aes_vectors(
        &unhex("0f0e0d0c0b0a09080706050403020100"),
        concat!(
            "20a8fb91b0495def0c16f6d760a39765",
            "5a1c9077eedb22dda2a186bba03801ab",
            "17449a6cde03bd17a43ed6910a0171dc",
            "aa420e667d4f033d0dd459f8ffd99625",
        ),
    );
}

#[test]
fn openpgp_cfb_matches_bouncy_castle_for_a_64_bit_gost_block() {
    struct GostKeyWithIv<'a> {
        key: &'a [u8],
        iv: &'a [u8],
    }
    impl KeyParams for GostKeyWithIv<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }
    impl Gost28147Params for GostKeyWithIv<'_> {
        fn s_box(&self) -> &[u8] {
            &s_box::DEFAULT
        }
    }
    impl IvParams for GostKeyWithIv<'_> {
        fn iv(&self) -> &[u8] {
            self.iv
        }
    }

    let key = unhex("0011223344556677889900112233445566778899001122334455667788990011");
    let iv = unhex("1234567890abcdef");
    let params = GostKeyWithIv { key: &key, iv: &iv };
    assert_vectors(
        &mut FixedOpenPgpCfbBlockCipher::<_, 8>::new(Gost28147Engine::new()),
        &params,
        &unhex("bc350e71aa113457bc350e71aa113457bc350e71aa113457"),
        &unhex("c6c2a8053293b60f086d9e34ae338a093e8924e84581c9a5"),
    );
}

#[test]
fn the_first_block_is_plain_full_block_cfb() {
    let key = unhex(KEY);
    let iv = unhex("0f0e0d0c0b0a09080706050403020100");
    let params = KeyWithIvRef::new(&key, &iv);
    let block = unhex("00112233445566778899aabbccddeeff");
    assert_eq!(
        process(&mut fixed(), CipherDirection::Encrypt, &params, &block),
        process(
            &mut FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new()),
            CipherDirection::Encrypt,
            &params,
            &block
        )
    );
}

#[test]
fn a_short_iv_is_right_aligned_over_zeros_so_an_empty_iv_is_all_zero() {
    let key = unhex(KEY);
    let run = |iv: &[u8]| {
        process(
            &mut fixed(),
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&key, iv),
            &[0x11; 48],
        )
    };
    let mut padded = [0; 16];
    padded[14..].copy_from_slice(&[0x12, 0x34]);
    assert_eq!(run(&[0x12, 0x34]), run(&padded));
    assert_eq!(run(&[]), run(&[0; 16]));
}

#[test]
fn reset_restarts_from_the_iv_as_a_first_block() {
    let key = unhex(KEY);
    let params = KeyWithIvRef::new(&key, &[]);
    let plaintext = unhex(PLAINTEXT);
    let mut mode = fixed();
    let first = process(&mut mode, CipherDirection::Encrypt, &params, &plaintext);
    mode.reset();
    let mut again = vec![0; plaintext.len()];
    for (input, output) in plaintext.chunks(16).zip(again.chunks_mut(16)) {
        mode.process_block(input, output).unwrap();
    }
    assert_eq!(first, again);
}

#[test]
fn an_iv_longer_than_the_block_and_an_engine_of_another_size_are_rejected() {
    let key = unhex(KEY);
    assert_eq!(
        fixed().init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &[0; 17])),
        Err(BlockModeInitError::InvalidIvLength(17))
    );
    assert_eq!(
        FixedOpenPgpCfbBlockCipher::<_, 8>::new(AesEngine::new())
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &[])),
        Err(BlockModeInitError::UnsupportedBlockSize {
            actual: 16,
            required: 8
        })
    );
}

#[test]
fn a_rejected_initialization_leaves_the_register_and_direction_untouched() {
    let key = unhex(KEY);
    let params = KeyWithIvRef::new(&key, &[]);
    let plaintext = unhex(PLAINTEXT);
    let expected = process(&mut fixed(), CipherDirection::Encrypt, &params, &plaintext);

    let mut mode = fixed();
    mode.init(CipherDirection::Encrypt, &params).unwrap();
    let mut output = vec![0; plaintext.len()];
    mode.process_block(&plaintext[..16], &mut output[..16])
        .unwrap();
    assert_eq!(
        mode.init(
            CipherDirection::Decrypt,
            &KeyWithIvRef::new(&key[..15], &[])
        ),
        Err(BlockModeInitError::Cipher(InitError::InvalidKeyLength(15)))
    );
    for (input, output) in plaintext[16..].chunks(16).zip(output[16..].chunks_mut(16)) {
        mode.process_block(input, output).unwrap();
    }
    assert_eq!(output, expected);
}

#[test]
fn processing_fails_before_initialization_and_on_short_buffers() {
    let mut mode = fixed();
    assert_eq!(
        mode.process_block(&[0; 16], &mut [0; 16]),
        Err(BlockModeError::NotInitialised)
    );

    let key = unhex(KEY);
    mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &[]))
        .unwrap();
    assert_eq!(
        mode.process_block(&[0; 15], &mut [0; 16]),
        Err(BlockModeError::BufferTooShort)
    );
    assert_eq!(
        mode.process_block(&[0; 16], &mut [0; 15]),
        Err(BlockModeError::BufferTooShort)
    );
    assert_only_the_first_segment_is_written(&mut mode);
}

#[test]
fn openpgp_cfb_reports_its_name_and_block_size_and_accepts_partial_blocks() {
    let mode = fixed();
    assert_eq!(mode.to_string(), "AES/OpenPGPCFB");
    assert_eq!(mode.block_size(), 16);
    assert!(mode.is_partial_block_okay());
}
