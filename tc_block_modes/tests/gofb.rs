//! GOFB: the Bouncy Castle GOST 28147 vectors, a long run through the counter
//! fix-up, plus direction, IV, reset and errors.

mod common;

use common::{assert_only_the_first_segment_is_written, assert_vectors, process, unhex};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, InitError, KeyParams};
use tc_block_modes::{
    BlockCipherMode, BlockModeError, BlockModeInitError, GofbBlockCipher, IvParams,
};
use tc_gost28147::{Gost28147Engine, Gost28147Params, s_box};

/// A GOST 28147 key, S-box and IV, as the engine and the mode need them.
struct GostKeyWithIv<'a> {
    key: &'a [u8],
    s_box: &'a [u8],
    iv: &'a [u8],
}

impl KeyParams for GostKeyWithIv<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Gost28147Params for GostKeyWithIv<'_> {
    fn s_box(&self) -> &[u8] {
        self.s_box
    }
}

impl IvParams for GostKeyWithIv<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

const KEY: &str = "0011223344556677889900112233445566778899001122334455667788990011";
const IV: &str = "1234567890abcdef";

/// The S-box of Bouncy Castle's GOFB tests with a custom table.
#[rustfmt::skip]
const TEST_S_BOX: [u8; 128] = [
    0xE, 0x3, 0xC, 0xD, 0x1, 0xF, 0xA, 0x9, 0xB, 0x6, 0x2, 0x7, 0x5, 0x0, 0x8, 0x4,
    0xD, 0x9, 0x0, 0x4, 0x7, 0x1, 0x3, 0xB, 0x6, 0xC, 0x2, 0xA, 0xF, 0xE, 0x5, 0x8,
    0x8, 0xB, 0xA, 0x7, 0x1, 0xD, 0x5, 0xC, 0x6, 0x3, 0x9, 0x0, 0xF, 0xE, 0x2, 0x4,
    0xD, 0x7, 0xC, 0x9, 0xF, 0x0, 0x5, 0x8, 0xA, 0x2, 0xB, 0x6, 0x4, 0x3, 0x1, 0xE,
    0xB, 0x4, 0x6, 0x5, 0x0, 0xF, 0x1, 0xC, 0x9, 0xE, 0xD, 0x8, 0x3, 0x7, 0xA, 0x2,
    0xD, 0xF, 0x9, 0x4, 0x2, 0xC, 0x5, 0xA, 0x6, 0x0, 0x3, 0x8, 0x7, 0xE, 0x1, 0xB,
    0xF, 0xE, 0x9, 0x5, 0xB, 0x2, 0x1, 0x8, 0x6, 0x0, 0xD, 0x3, 0x4, 0x7, 0xC, 0xA,
    0xA, 0x3, 0xE, 0x2, 0x0, 0x1, 0x4, 0x6, 0xB, 0x8, 0xC, 0x7, 0xD, 0x5, 0xF, 0x9,
];

fn mode() -> GofbBlockCipher<Gost28147Engine> {
    GofbBlockCipher::new(Gost28147Engine::new())
}

#[test]
fn gofb_matches_the_bouncy_castle_vector_with_the_default_s_box() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = GostKeyWithIv {
        key: &key,
        s_box: &s_box::DEFAULT,
        iv: &iv,
    };
    assert_vectors(
        &mut mode(),
        &params,
        &unhex("bc350e71aa113457"),
        &unhex("8824c124c4fd1430"),
    );
}

#[test]
fn gofb_matches_the_bouncy_castle_vectors_with_a_custom_s_box() {
    let key = unhex("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993");
    for (iv, plaintext, ciphertext) in [
        (
            "8001069080010690",
            "094C912C5EFDD703D42118971694580B",
            "2707B58DF039D1A64460735FFE76D55F",
        ),
        (
            "800107A0800107A0",
            "FE780800E0690083F20C010CF00C0329",
            "9AF623DFF948B413B53171E8D546188D",
        ),
    ] {
        let iv = unhex(iv);
        let params = GostKeyWithIv {
            key: &key,
            s_box: &TEST_S_BOX,
            iv: &iv,
        };
        assert_vectors(&mut mode(), &params, &unhex(plaintext), &unhex(ciphertext));
    }
}

#[test]
fn a_long_run_through_sixteen_counter_fix_ups_matches_bouncy_castle() {
    // Bouncy Castle's GOFBBlockCipher, run over 4096 zero blocks, applies its
    // modulo 2^32 - 1 fix-up to the high counter word 16 times.
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = GostKeyWithIv {
        key: &key,
        s_box: &s_box::DEFAULT,
        iv: &iv,
    };
    let output = process(
        &mut mode(),
        CipherDirection::Encrypt,
        &params,
        &[0; 8 * 4096],
    );
    assert_eq!(&output[output.len() - 8..], unhex("1cfce9adf6119872"));
}

#[test]
fn the_requested_direction_does_not_change_the_gofb_output() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = GostKeyWithIv {
        key: &key,
        s_box: &s_box::DEFAULT,
        iv: &iv,
    };
    let input = [0x5a; 24];
    assert_eq!(
        process(&mut mode(), CipherDirection::Encrypt, &params, &input),
        process(&mut mode(), CipherDirection::Decrypt, &params, &input)
    );
}

#[test]
fn a_short_iv_is_right_aligned_over_zeros_so_an_empty_iv_is_all_zero() {
    let key = unhex(KEY);
    let run = |iv: &[u8]| {
        let params = GostKeyWithIv {
            key: &key,
            s_box: &s_box::DEFAULT,
            iv,
        };
        process(&mut mode(), CipherDirection::Encrypt, &params, &[0x11; 16])
    };
    assert_eq!(run(&[0x12, 0x34]), run(&[0, 0, 0, 0, 0, 0, 0x12, 0x34]));
    assert_eq!(run(&[]), run(&[0; 8]));
}

#[test]
fn reset_restarts_the_keystream_from_the_iv() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = GostKeyWithIv {
        key: &key,
        s_box: &s_box::DEFAULT,
        iv: &iv,
    };
    let mut gofb = mode();
    let first = process(&mut gofb, CipherDirection::Encrypt, &params, &[0; 24]);
    gofb.reset();
    let mut again = [0; 24];
    for (input, output) in [0; 24].chunks(8).zip(again.chunks_mut(8)) {
        gofb.process_block(input, output).unwrap();
    }
    assert_eq!(first, again);
}

#[test]
fn an_iv_longer_than_the_block_and_an_engine_that_is_not_64_bit_are_rejected() {
    let key = unhex(KEY);
    let params = GostKeyWithIv {
        key: &key,
        s_box: &s_box::DEFAULT,
        iv: &[0; 9],
    };
    assert_eq!(
        mode().init(CipherDirection::Encrypt, &params),
        Err(BlockModeInitError::InvalidIvLength(9))
    );

    let aes_key = [0; 16];
    let mut aes = GofbBlockCipher::new(AesEngine::new());
    assert_eq!(
        aes.init(
            CipherDirection::Encrypt,
            &tc_block_modes::KeyWithIvRef::new(&aes_key, &[0; 8])
        ),
        Err(BlockModeInitError::UnsupportedBlockSize {
            actual: 16,
            required: 8
        })
    );
}

#[test]
fn a_rejected_initialization_leaves_the_counter_untouched() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = GostKeyWithIv {
        key: &key,
        s_box: &s_box::DEFAULT,
        iv: &iv,
    };
    let expected = process(&mut mode(), CipherDirection::Encrypt, &params, &[0; 16]);

    let mut gofb = mode();
    gofb.init(CipherDirection::Encrypt, &params).unwrap();
    let mut output = [0; 16];
    gofb.process_block(&[0; 8], &mut output[..8]).unwrap();
    let short_key = GostKeyWithIv {
        key: &key[..31],
        s_box: &s_box::DEFAULT,
        iv: &iv,
    };
    assert_eq!(
        gofb.init(CipherDirection::Encrypt, &short_key),
        Err(BlockModeInitError::Cipher(InitError::InvalidKeyLength(31)))
    );
    gofb.process_block(&[0; 8], &mut output[8..]).unwrap();
    assert_eq!(output.as_slice(), expected);
}

#[test]
fn processing_fails_before_initialization_and_on_short_buffers() {
    let mut gofb = mode();
    assert_eq!(
        gofb.process_block(&[0; 8], &mut [0; 8]),
        Err(BlockModeError::NotInitialised)
    );

    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = GostKeyWithIv {
        key: &key,
        s_box: &s_box::DEFAULT,
        iv: &iv,
    };
    gofb.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        gofb.process_block(&[0; 7], &mut [0; 8]),
        Err(BlockModeError::BufferTooShort)
    );
    assert_eq!(
        gofb.process_block(&[0; 8], &mut [0; 7]),
        Err(BlockModeError::BufferTooShort)
    );
    assert_only_the_first_segment_is_written(&mut gofb);
}

#[test]
fn gofb_reports_its_name_and_block_size_and_accepts_partial_blocks() {
    let gofb = mode();
    assert_eq!(gofb.to_string(), "Gost28147/GCTR");
    assert_eq!(gofb.block_size(), 8);
    assert!(gofb.is_partial_block_okay());
}
