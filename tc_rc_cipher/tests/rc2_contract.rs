//! State, buffer and initialization contracts for the RC2 engines.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
#[cfg(feature = "rustcrypto")]
use tc_rc_cipher::Rc2RustCryptoEngine;
use tc_rc_cipher::{
    RC2_ALGO_NAME, RC2_BLOCK_BYTES, RC2_MAX_EFFECTIVE_KEY_BITS, RC2_MAX_KEY_BYTES, Rc2Engine,
    Rc2TableEngine,
};
use tc_rc_cipher::{Rc2Params, Rc2ParamsRef};

fn check_contract<E>(
    mut engine: E,
    key_len: usize,
    block_bytes: usize,
    name: &str,
    invalid: &[usize],
    effective_bits: usize,
) where
    E: core::fmt::Display
        + BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<Rc2ParamsRef<'a>, Error = InitError>
        + 'static,
{
    let mut untouched = vec![0x55; block_bytes + 4];
    assert_eq!(engine.block_size(), block_bytes);
    assert_eq!(engine.to_string(), name);
    assert_eq!(
        engine.process_block(&[], &mut untouched),
        Err(BlockError::NotInitialised)
    );
    assert_eq!(untouched, vec![0x55; block_bytes + 4]);

    for &length in invalid {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &Rc2ParamsRef::new(&vec![0; length])
            ),
            Err(InitError::InvalidKeyLength(length))
        );
        assert_eq!(
            engine.process_block(&vec![0; block_bytes], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, vec![0x55; block_bytes + 4]);
    }

    let key = vec![0x42; key_len];
    for bits in [0, RC2_MAX_EFFECTIVE_KEY_BITS + 1, usize::MAX] {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &Rc2ParamsRef::with_effective_key_bits(&key, bits)
            ),
            Err(InitError::InvalidEffectiveKeyBits(bits))
        );
        assert_eq!(
            engine.process_block(&[], &mut untouched),
            Err(BlockError::NotInitialised)
        );
        assert_eq!(untouched, vec![0x55; block_bytes + 4]);
    }
    let plaintext = vec![0x11; block_bytes + 4];
    let params = Rc2ParamsRef::with_effective_key_bits(&key, effective_bits);
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = vec![0x55; block_bytes + 4];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted),
        Ok(block_bytes)
    );
    assert_eq!(&encrypted[block_bytes..], &[0x55; 4]);

    for (direction, opposite, input, expected) in [
        (
            CipherDirection::Encrypt,
            CipherDirection::Decrypt,
            &plaintext,
            &encrypted,
        ),
        (
            CipherDirection::Decrypt,
            CipherDirection::Encrypt,
            &encrypted,
            &plaintext,
        ),
    ] {
        engine.init(direction, &params).unwrap();
        for &length in invalid {
            assert_eq!(
                engine.init(opposite, &Rc2ParamsRef::new(&vec![0; length])),
                Err(InitError::InvalidKeyLength(length))
            );
            let mut actual = vec![0x55; block_bytes + 4];
            assert_eq!(engine.process_block(input, &mut actual), Ok(block_bytes));
            assert_eq!(&actual[..block_bytes], &expected[..block_bytes]);
            assert_eq!(&actual[block_bytes..], &[0x55; 4]);
        }
        for bits in [0, RC2_MAX_EFFECTIVE_KEY_BITS + 1, usize::MAX] {
            assert_eq!(
                engine.init(opposite, &Rc2ParamsRef::with_effective_key_bits(&key, bits)),
                Err(InitError::InvalidEffectiveKeyBits(bits))
            );
            let mut actual = vec![0x55; block_bytes + 4];
            engine.process_block(input, &mut actual).unwrap();
            assert_eq!(&actual[..block_bytes], &expected[..block_bytes]);
            assert_eq!(&actual[block_bytes..], &[0x55; 4]);
        }
        for length in [0, block_bytes - 1] {
            assert_eq!(
                engine.process_block(&input[..length], &mut untouched),
                Err(BlockError::BufferTooShort)
            );
            assert_eq!(untouched, vec![0x55; block_bytes + 4]);
            assert_eq!(
                engine.process_block(input, &mut untouched[..length]),
                Err(BlockError::BufferTooShort)
            );
            assert_eq!(untouched, vec![0x55; block_bytes + 4]);
        }
        assert_eq!(engine.to_string(), name);
    }

    let mut cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    assert_eq!(cipher.block_size(), block_bytes);
    let mut recovered = vec![0x55; block_bytes + 4];
    assert_eq!(
        cipher.process_block(&encrypted, &mut recovered),
        Ok(block_bytes)
    );
    assert_eq!(&recovered[..block_bytes], &plaintext[..block_bytes]);
    assert_eq!(&recovered[block_bytes..], &[0x55; 4]);
}

#[test]
fn rc2_preserves_state_and_buffers_for_every_key_length_and_effective_size_boundaries() {
    for size in 1..=RC2_MAX_KEY_BYTES {
        for bits in [1, 63, size * 8, RC2_MAX_EFFECTIVE_KEY_BITS] {
            check_contract(
                Rc2Engine::new(),
                size,
                RC2_BLOCK_BYTES,
                RC2_ALGO_NAME,
                &[0, RC2_MAX_KEY_BYTES + 1],
                bits,
            );
            check_contract(
                Rc2Engine::default(),
                size,
                RC2_BLOCK_BYTES,
                RC2_ALGO_NAME,
                &[0, RC2_MAX_KEY_BYTES + 1],
                bits,
            );
            check_contract(
                Rc2TableEngine::new(),
                size,
                RC2_BLOCK_BYTES,
                RC2_ALGO_NAME,
                &[0, RC2_MAX_KEY_BYTES + 1],
                bits,
            );
            #[cfg(feature = "rustcrypto")]
            check_contract(
                Rc2RustCryptoEngine::new(),
                size,
                RC2_BLOCK_BYTES,
                RC2_ALGO_NAME,
                &[0, RC2_MAX_KEY_BYTES + 1],
                bits,
            );
        }
    }
}

#[test]
fn every_valid_effective_bit_count_can_be_selected_independently_of_key_length() {
    let mut engine = Rc2Engine::new();
    for bits in 1..=RC2_MAX_EFFECTIVE_KEY_BITS {
        let params = Rc2ParamsRef::with_effective_key_bits(&[0x42; 7], bits);
        let mut encrypted = [0; RC2_BLOCK_BYTES];
        let mut recovered = [0; RC2_BLOCK_BYTES];
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        engine
            .process_block(&[0x11; RC2_BLOCK_BYTES], &mut encrypted)
            .unwrap();
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_block(&encrypted, &mut recovered).unwrap();
        assert_eq!(recovered, [0x11; RC2_BLOCK_BYTES]);
    }
}

struct ThirdPartyParams<'a> {
    key: &'a [u8],
    effective_key_bits: usize,
}

impl KeyParams for ThirdPartyParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Rc2Params for ThirdPartyParams<'_> {
    fn effective_key_bits(&self) -> usize {
        self.effective_key_bits
    }
}

#[test]
fn accepts_third_party_params_and_supports_dynamic_dispatch() {
    let params = ThirdPartyParams {
        key: &[0u8; 8],
        effective_key_bits: 63,
    };
    let mut engine = Rc2Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    let mut output = [0u8; RC2_BLOCK_BYTES];
    assert_eq!(
        cipher.process_block(&[0u8; RC2_BLOCK_BYTES], &mut output),
        Ok(RC2_BLOCK_BYTES)
    );
    assert_eq!(output, [0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff]);
}
