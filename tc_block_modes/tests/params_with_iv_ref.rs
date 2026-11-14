//! ParamsWithIvRef: borrowed parameters through the modes with an IV, without
//! the `alloc` feature for the fixed-size modes, including a trait object.

mod common;

use common::{process, unhex};
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_block_modes::{
    BlockModeInitError, FixedCbcBlockCipher, FixedCfbBlockCipher, FixedCtrBlockCipher,
    FixedKctrBlockCipher, FixedOfbBlockCipher, FixedOpenPgpCfbBlockCipher, GofbBlockCipher,
    KeyWithIvRef, ParamsWithIvRef,
};
use tc_gost28147::{Gost28147Engine, Gost28147ParamsRef, s_box};
use tc_rc_cipher::{Rc2Engine, Rc2Params, Rc2ParamsRef};

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const IV: &str = "000102030405060708090a0b0c0d0e0f";

fn message() -> Vec<u8> {
    (0..64).map(|index| index as u8 ^ 0x5a).collect()
}

/// Encrypts the message with `mode` under `KeyWithIvRef` and
/// `ParamsWithIvRef<KeyRef>`, which must agree, and checks that the result
/// decrypts back.
fn assert_same_as_key_with_iv<M>(mut mode: M)
where
    M: BlockCipher
        + for<'a> BlockCipherInit<KeyWithIvRef<'a>>
        + for<'a> BlockCipherInit<ParamsWithIvRef<'a, KeyRef<'a>>>,
{
    let (key, iv) = (unhex(KEY), unhex(IV));
    let message = message();
    let key_with_iv = KeyWithIvRef::new(&key, &iv);
    let inner = KeyRef::new(&key);
    let params_with_iv = ParamsWithIvRef::new(&inner, &iv);

    let expected = process(&mut mode, CipherDirection::Encrypt, &key_with_iv, &message);
    let actual = process(
        &mut mode,
        CipherDirection::Encrypt,
        &params_with_iv,
        &message,
    );
    assert_eq!(actual, expected);
    let recovered = process(
        &mut mode,
        CipherDirection::Decrypt,
        &params_with_iv,
        &actual,
    );
    assert_eq!(recovered, message);
}

#[test]
fn a_borrowed_key_with_an_iv_gives_what_key_with_iv_ref_gives_in_every_mode() {
    assert_same_as_key_with_iv(FixedCbcBlockCipher::<_, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedOfbBlockCipher::<_, 16, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedCtrBlockCipher::<_, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedKctrBlockCipher::<_, 16>::new(AesEngine::new()));
    assert_same_as_key_with_iv(FixedOpenPgpCfbBlockCipher::<_, 16>::new(AesEngine::new()));
    #[cfg(feature = "alloc")]
    {
        use tc_block_modes::{
            CbcBlockCipher, CfbBlockCipher, CtrBlockCipher, KctrBlockCipher, OfbBlockCipher,
            OpenPgpCfbBlockCipher,
        };
        assert_same_as_key_with_iv(CbcBlockCipher::new(AesEngine::new()));
        assert_same_as_key_with_iv(CfbBlockCipher::new(AesEngine::new(), 8));
        assert_same_as_key_with_iv(OfbBlockCipher::new(AesEngine::new(), 128));
        assert_same_as_key_with_iv(CtrBlockCipher::new(AesEngine::new()));
        assert_same_as_key_with_iv(KctrBlockCipher::new(AesEngine::new()));
        assert_same_as_key_with_iv(OpenPgpCfbBlockCipher::new(AesEngine::new()));
    }
}

#[test]
fn rc2_in_a_fixed_cbc_takes_its_effective_key_bits_through_a_trait_object() {
    let key = unhex("88bca90e90875a7f0f79c384627bafb2");
    let iv = unhex("0001020304050607");
    let message = message();
    let rc2 = Rc2ParamsRef::with_effective_key_bits(&key, 40);

    let mut mode = FixedCbcBlockCipher::<_, 8>::new(Rc2Engine::new());
    let ciphertext = process(
        &mut mode,
        CipherDirection::Encrypt,
        &ParamsWithIvRef::new(&rc2, &iv),
        &message,
    );

    // CBC by hand over the engine, initialized with the same RC2 parameters
    let mut engine = Rc2Engine::new();
    engine.init(CipherDirection::Encrypt, &rc2).unwrap();
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

    // The same parameters behind `dyn Rc2Params`
    let dynamic: &dyn Rc2Params = &rc2;
    let recovered = process(
        &mut mode,
        CipherDirection::Decrypt,
        &ParamsWithIvRef::new(dynamic, &iv),
        &ciphertext,
    );
    assert_eq!(recovered, message);
}

#[test]
fn gost28147_in_gofb_takes_its_s_box_from_borrowed_params() {
    let key = unhex("0011223344556677889900112233445566778899001122334455667788990011");
    let iv = unhex("1234567890abcdef");
    let gost = Gost28147ParamsRef::with_s_box(&key, &s_box::DEFAULT);
    // Bouncy Castle's GOFB vector with the default S-box
    let ciphertext = process(
        &mut GofbBlockCipher::new(Gost28147Engine::new()),
        CipherDirection::Encrypt,
        &ParamsWithIvRef::new(&gost, &iv),
        &unhex("bc350e71aa113457"),
    );
    assert_eq!(ciphertext, unhex("8824c124c4fd1430"));
}

#[test]
fn an_iv_a_mode_cannot_take_is_still_refused() {
    let key = unhex(KEY);
    let inner = KeyRef::new(&key);
    for length in [0, 15, 17] {
        let iv = vec![0; length];
        assert_eq!(
            FixedCbcBlockCipher::<_, 16>::new(AesEngine::new())
                .init(CipherDirection::Encrypt, &ParamsWithIvRef::new(&inner, &iv)),
            Err(BlockModeInitError::InvalidIvLength(length))
        );
    }
    let iv = [0; 17];
    assert_eq!(
        FixedCtrBlockCipher::<_, 16>::new(AesEngine::new())
            .init(CipherDirection::Encrypt, &ParamsWithIvRef::new(&inner, &iv)),
        Err(BlockModeInitError::InvalidIvLength(17))
    );
}

#[test]
fn debug_shows_the_inner_params_and_only_the_iv_length() {
    let key = unhex(KEY);
    let rc2 = Rc2ParamsRef::new(&key);
    let params = ParamsWithIvRef::new(&rc2, &[0; 8]);
    assert_eq!(
        format!("{params:?}"),
        format!("ParamsWithIvRef {{ params: {rc2:?}, iv_len: 8 }}")
    );
}
