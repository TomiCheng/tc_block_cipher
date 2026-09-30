//! RC2 vectors from Bouncy Castle's `RC2Test.cs` and RFC 2268.

mod common;

use common::unhex;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_rc_cipher::Rc2ParamsRef;
#[cfg(feature = "rustcrypto")]
use tc_rc_cipher::Rc2RustCryptoEngine;
use tc_rc_cipher::{RC2_BLOCK_BYTES, Rc2Engine, Rc2TableEngine};

fn assert_vector<E>(
    new: fn() -> E,
    key: &str,
    effective_key_bits: usize,
    plaintext: &str,
    ciphertext: &str,
) where
    E: BlockCipher + for<'a> BlockCipherInit<Rc2ParamsRef<'a>>,
{
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = Rc2ParamsRef::with_effective_key_bits(&key, effective_key_bits);
    let mut engine = new();
    let mut output = [0u8; RC2_BLOCK_BYTES];

    assert!(engine.init(CipherDirection::Encrypt, &params).is_ok());
    assert!(matches!(
        engine.process_block(&plaintext, &mut output),
        Ok(RC2_BLOCK_BYTES)
    ));
    assert_eq!(output.as_slice(), ciphertext);

    assert!(engine.init(CipherDirection::Decrypt, &params).is_ok());
    assert!(engine.process_block(&ciphertext, &mut output).is_ok());
    assert_eq!(output.as_slice(), plaintext);
}

fn assert_all_vectors<E>(new: fn() -> E)
where
    E: BlockCipher + for<'a> BlockCipherInit<Rc2ParamsRef<'a>>,
{
    assert_vector(
        new,
        "0000000000000000",
        63,
        "0000000000000000",
        "ebb773f993278eff",
    );
    assert_vector(
        new,
        "ffffffffffffffff",
        64,
        "ffffffffffffffff",
        "278b27e42e2f0d49",
    );
    assert_vector(
        new,
        "3000000000000000",
        64,
        "1000000000000001",
        "30649edf9be7d2c2",
    );
    assert_vector(new, "88", 64, "0000000000000000", "61a8a244adacccf0");
    assert_vector(
        new,
        "88bca90e90875a",
        64,
        "0000000000000000",
        "6ccf4308974c267f",
    );
    assert_vector(
        new,
        "88bca90e90875a7f0f79c384627bafb2",
        64,
        "0000000000000000",
        "1a807d272bbe5db1",
    );
    assert_vector(
        new,
        "88bca90e90875a7f0f79c384627bafb2",
        128,
        "0000000000000000",
        "2269552ab0f85ca6",
    );
    assert_vector(
        new,
        "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
        129,
        "0000000000000000",
        "5b78d3a43dfff1f1",
    );
}

#[test]
fn rc2_matches_all_rfc_and_bouncy_castle_vectors_in_both_directions() {
    assert_all_vectors(Rc2Engine::new);
    assert_all_vectors(Rc2TableEngine::new);
    #[cfg(feature = "rustcrypto")]
    assert_all_vectors(Rc2RustCryptoEngine::new);
}
