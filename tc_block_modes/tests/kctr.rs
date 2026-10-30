//! KCTR: the Bouncy Castle DSTU 7624 vectors, a long run through counter
//! carries, plus direction, IV, reset and errors.

mod common;

use common::{assert_only_the_first_segment_is_written, assert_vectors, process, unhex};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, InitError};
use tc_block_modes::{
    BlockCipherMode, BlockModeError, BlockModeInitError, FixedKctrBlockCipher, KeyWithIvRef,
};
use tc_dstu7624::{Dstu7624Engine128, Dstu7624Engine256};

const KEY: &str = "000102030405060708090A0B0C0D0E0F";
const IV: &str = "101112131415161718191A1B1C1D1E1F";

type FixedKalynaKctr = FixedKctrBlockCipher<Dstu7624Engine128, 16>;

fn fixed() -> FixedKalynaKctr {
    FixedKalynaKctr::new(Dstu7624Engine128::new())
}

#[test]
fn kctr_matches_the_bouncy_castle_dstu7624_vector() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let plaintext = unhex("303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
    let ciphertext = unhex("B91A7B8790BBCFCFE65D04E5538E98E216AC209DA33122FDA596E8928070BE51");

    assert_vectors(&mut fixed(), &params, &plaintext, &ciphertext);
    #[cfg(feature = "alloc")]
    assert_vectors(
        &mut tc_block_modes::KctrBlockCipher::new(Dstu7624Engine128::new()),
        &params,
        &plaintext,
        &ciphertext,
    );
}

#[test]
fn a_final_partial_block_matches_the_bouncy_castle_stream_vector() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let plaintext =
        unhex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    let ciphertext =
        unhex("A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A");

    let mut kctr = fixed();
    kctr.init(CipherDirection::Encrypt, &params).unwrap();
    let mut output = vec![0; plaintext.len()];
    for (input, output) in plaintext.chunks(16).zip(output.chunks_mut(16)) {
        let mut block = [0; 16];
        block[..input.len()].copy_from_slice(input);
        let mut keyed = [0; 16];
        kctr.process_block(&block, &mut keyed).unwrap();
        output.copy_from_slice(&keyed[..output.len()]);
    }
    assert_eq!(output, ciphertext);
}

#[test]
fn a_long_run_through_counter_carries_matches_bouncy_castle() {
    // 1024 blocks carry out of the counter's low byte at least three times.
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let output = process(
        &mut fixed(),
        CipherDirection::Encrypt,
        &params,
        &[0; 16 * 1024],
    );
    assert_eq!(
        &output[output.len() - 16..],
        unhex("54650e1174f8fc6c25eefc3a681ae6a7")
    );
}

#[test]
fn kctr_over_a_256_bit_block_matches_bouncy_castle() {
    let key = unhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let iv = unhex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    let params = KeyWithIvRef::new(&key, &iv);
    let plaintext: Vec<u8> = (0x40..0x80).collect();
    let ciphertext = unhex(concat!(
        "5ee17c749b751c91635bc0cffd0ea12f4078695e9cc460aa28871f8dd3d479f5",
        "8be1e390cdf34b934c320bd34855092f1fbe52f88546547921ec61ecab4e5e60",
    ));

    assert_vectors(
        &mut FixedKctrBlockCipher::<_, 32>::new(Dstu7624Engine256::new()),
        &params,
        &plaintext,
        &ciphertext,
    );
    #[cfg(feature = "alloc")]
    assert_vectors(
        &mut tc_block_modes::KctrBlockCipher::new(Dstu7624Engine256::new()),
        &params,
        &plaintext,
        &ciphertext,
    );
}

#[test]
fn the_requested_direction_does_not_change_the_kctr_output() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let input = [0x5a; 48];
    assert_eq!(
        process(&mut fixed(), CipherDirection::Encrypt, &params, &input),
        process(&mut fixed(), CipherDirection::Decrypt, &params, &input)
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
            &[0x11; 32],
        )
    };
    let mut padded = [0; 16];
    padded[14..].copy_from_slice(&[0x12, 0x34]);
    assert_eq!(run(&[0x12, 0x34]), run(&padded));
    assert_eq!(run(&[]), run(&[0; 16]));
}

#[test]
fn reset_restarts_the_keystream_from_the_iv() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let mut kctr = fixed();
    let first = process(&mut kctr, CipherDirection::Encrypt, &params, &[0; 48]);
    kctr.reset();
    let mut again = [0; 48];
    for (input, output) in [0; 48].chunks(16).zip(again.chunks_mut(16)) {
        kctr.process_block(input, output).unwrap();
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
        FixedKctrBlockCipher::<_, 32>::new(AesEngine::new())
            .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &[])),
        Err(BlockModeInitError::UnsupportedBlockSize {
            actual: 16,
            required: 32
        })
    );
}

#[test]
fn a_rejected_initialization_leaves_the_counter_untouched() {
    let (key, iv) = (unhex(KEY), unhex(IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let expected = process(&mut fixed(), CipherDirection::Encrypt, &params, &[0; 32]);

    let mut kctr = fixed();
    kctr.init(CipherDirection::Encrypt, &params).unwrap();
    let mut output = [0; 32];
    kctr.process_block(&[0; 16], &mut output[..16]).unwrap();
    assert_eq!(
        kctr.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&key[..15], &iv)
        ),
        Err(BlockModeInitError::Cipher(InitError::InvalidKeyLength(15)))
    );
    kctr.process_block(&[0; 16], &mut output[16..]).unwrap();
    assert_eq!(output.as_slice(), expected);
}

#[test]
fn processing_fails_before_initialization_and_on_short_buffers() {
    let mut kctr = fixed();
    assert_eq!(
        kctr.process_block(&[0; 16], &mut [0; 16]),
        Err(BlockModeError::NotInitialised)
    );

    let (key, iv) = (unhex(KEY), unhex(IV));
    kctr.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))
        .unwrap();
    assert_eq!(
        kctr.process_block(&[0; 15], &mut [0; 16]),
        Err(BlockModeError::BufferTooShort)
    );
    assert_eq!(
        kctr.process_block(&[0; 16], &mut [0; 15]),
        Err(BlockModeError::BufferTooShort)
    );
    assert_only_the_first_segment_is_written(&mut kctr);
}

#[test]
fn kctr_reports_its_name_and_block_size_and_accepts_partial_blocks() {
    let kctr = fixed();
    assert_eq!(kctr.to_string(), "DSTU7624/KCTR");
    assert_eq!(kctr.block_size(), 16);
    assert!(kctr.is_partial_block_okay());
}
