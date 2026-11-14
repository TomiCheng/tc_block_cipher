//! ParamsWithIvOwned: an engine's own parameters through the modes with an IV,
//! the same output as KeyWithIvOwned for a bare key, and the IV lengths each
//! mode still checks.
#![cfg(feature = "alloc")]

mod common;

use common::{process, unhex};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyOwned};
use tc_block_modes::{
    BlockModeInitError, CbcBlockCipher, CfbBlockCipher, CtrBlockCipher, FixedCbcBlockCipher,
    FixedCfbBlockCipher, FixedCtrBlockCipher, FixedKctrBlockCipher, FixedOfbBlockCipher,
    FixedOpenPgpCfbBlockCipher, GofbBlockCipher, KctrBlockCipher, KeyWithIvOwned, OfbBlockCipher,
    OpenPgpCfbBlockCipher, ParamsWithIvOwned,
};
use tc_gost28147::{Gost28147Engine, Gost28147ParamsOwned, s_box};
use tc_rc_cipher::{Rc2Engine, Rc2ParamsOwned};

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const IV: &str = "000102030405060708090a0b0c0d0e0f";

fn message() -> Vec<u8> {
    (0..64).map(|index| index as u8 ^ 0x5a).collect()
}

fn key_with_iv() -> KeyWithIvOwned {
    KeyWithIvOwned::new(unhex(KEY), unhex(IV))
}

fn params_with_iv() -> ParamsWithIvOwned<KeyOwned> {
    ParamsWithIvOwned::new(KeyOwned::new(unhex(KEY)), unhex(IV))
}

/// Encrypts the message with `mode` under both parameter types, which must
/// agree, and checks that the result decrypts back.
fn assert_same_as_key_with_iv<M>(mut mode: M)
where
    M: BlockCipher + BlockCipherInit<KeyWithIvOwned> + BlockCipherInit<ParamsWithIvOwned<KeyOwned>>,
{
    let message = message();
    let expected = process(
        &mut mode,
        CipherDirection::Encrypt,
        &key_with_iv(),
        &message,
    );
    let actual = process(
        &mut mode,
        CipherDirection::Encrypt,
        &params_with_iv(),
        &message,
    );
    assert_eq!(actual, expected);
    let recovered = process(
        &mut mode,
        CipherDirection::Decrypt,
        &params_with_iv(),
        &actual,
    );
    assert_eq!(recovered, message);
}

#[test]
fn a_bare_key_with_an_iv_gives_what_key_with_iv_owned_gives_in_every_mode() {
    assert_same_as_key_with_iv(CbcBlockCipher::new(AesEngine::new()));
    assert_same_as_key_with_iv(CfbBlockCipher::new(AesEngine::new(), 128));
    assert_same_as_key_with_iv(CfbBlockCipher::new(AesEngine::new(), 8));
    assert_same_as_key_with_iv(OfbBlockCipher::new(AesEngine::new(), 128));
    assert_same_as_key_with_iv(CtrBlockCipher::new(AesEngine::new()));
    assert_same_as_key_with_iv(KctrBlockCipher::new(AesEngine::new()));
    assert_same_as_key_with_iv(OpenPgpCfbBlockCipher::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedCbcBlockCipher::<_, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedOfbBlockCipher::<_, 16, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedCtrBlockCipher::<_, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedKctrBlockCipher::<_, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedOpenPgpCfbBlockCipher::<_, 16>::new(AesEngine::new()));
}

#[test]
fn rc2_in_cbc_takes_its_effective_key_bits_and_chains_as_cbc_by_hand() {
    let key = unhex("88bca90e90875a7f0f79c384627bafb2");
    let iv = unhex("0001020304050607");
    let message = message();
    let rc2 = || Rc2ParamsOwned::with_effective_key_bits(key.clone(), 40);

    let mut mode = CbcBlockCipher::new(Rc2Engine::new());
    let params = ParamsWithIvOwned::new(rc2(), iv.clone());
    let ciphertext = process(&mut mode, CipherDirection::Encrypt, &params, &message);

    // CBC by hand over the engine, initialized with the same RC2 parameters
    let mut engine = Rc2Engine::new();
    engine.init(CipherDirection::Encrypt, &rc2()).unwrap();
    let mut chain = iv.clone();
    let mut expected = Vec::new();
    for block in message.chunks(8) {
        let input: Vec<u8> = block.iter().zip(&chain).map(|(m, c)| m ^ c).collect();
        let mut output = [0; 8];
        engine.process_block(&input, &mut output).unwrap();
        chain = output.to_vec();
        expected.extend_from_slice(&output);
    }
    assert_eq!(ciphertext, expected);

    // 40 effective bits is not the 128 the key's length would give
    let full = ParamsWithIvOwned::new(Rc2ParamsOwned::new(key.clone()), iv.clone());
    assert_ne!(
        process(&mut mode, CipherDirection::Encrypt, &full, &message),
        ciphertext
    );

    let recovered = process(&mut mode, CipherDirection::Decrypt, &params, &ciphertext);
    assert_eq!(recovered, message);
}

#[test]
fn gost28147_in_gofb_takes_its_s_box_from_the_inner_params() {
    let key = unhex("0011223344556677889900112233445566778899001122334455667788990011");
    let params = ParamsWithIvOwned::new(
        Gost28147ParamsOwned::with_s_box(key, s_box::DEFAULT.to_vec()),
        unhex("1234567890abcdef"),
    );
    // Bouncy Castle's GOFB vector with the default S-box
    let mut mode = GofbBlockCipher::new(Gost28147Engine::new());
    let ciphertext = process(
        &mut mode,
        CipherDirection::Encrypt,
        &params,
        &unhex("bc350e71aa113457"),
    );
    assert_eq!(ciphertext, unhex("8824c124c4fd1430"));
}

#[test]
fn each_mode_still_refuses_an_iv_it_cannot_take() {
    let iv_of = |length| ParamsWithIvOwned::new(KeyOwned::new(unhex(KEY)), vec![0; length]);
    let refused = |length| Err(BlockModeInitError::InvalidIvLength(length));
    let encrypt = CipherDirection::Encrypt;

    // CBC takes exactly one block
    for length in [0, 15, 17] {
        let params = iv_of(length);
        assert_eq!(
            CbcBlockCipher::new(AesEngine::new()).init(encrypt, &params),
            refused(length)
        );
        assert_eq!(
            FixedCbcBlockCipher::<_, 16>::new(AesEngine::new()).init(encrypt, &params),
            refused(length)
        );
    }

    // The others take up to one block
    let params = iv_of(17);
    assert_eq!(
        CfbBlockCipher::new(AesEngine::new(), 128).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        OfbBlockCipher::new(AesEngine::new(), 128).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        CtrBlockCipher::new(AesEngine::new()).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        KctrBlockCipher::new(AesEngine::new()).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        OpenPgpCfbBlockCipher::new(AesEngine::new()).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new()).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        FixedOfbBlockCipher::<_, 16, 16>::new(AesEngine::new()).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        FixedCtrBlockCipher::<_, 16>::new(AesEngine::new()).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        FixedKctrBlockCipher::<_, 16>::new(AesEngine::new()).init(encrypt, &params),
        refused(17)
    );
    assert_eq!(
        FixedOpenPgpCfbBlockCipher::<_, 16>::new(AesEngine::new()).init(encrypt, &params),
        refused(17)
    );

    let gost = ParamsWithIvOwned::new(Gost28147ParamsOwned::new(vec![0; 32]), vec![0; 9]);
    assert_eq!(
        GofbBlockCipher::new(Gost28147Engine::new()).init(encrypt, &gost),
        refused(9)
    );
}

#[test]
fn debug_shows_the_inner_params_and_only_the_iv_length() {
    let params = ParamsWithIvOwned::new(Rc2ParamsOwned::new(unhex(KEY)), unhex(IV));
    assert_eq!(
        format!("{params:?}"),
        format!(
            "ParamsWithIvOwned {{ params: {:?}, iv_len: 16 }}",
            params.params()
        )
    );
}
