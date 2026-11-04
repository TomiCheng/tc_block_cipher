//! Blowfish vectors from Bouncy Castle's `BlowfishTest.cs`.

mod common;

use common::unhex;
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};
#[cfg(feature = "rustcrypto")]
use tc_blowfish::BlowfishRustCryptoEngine;
use tc_blowfish::{BLOCK_BYTES, BlowfishEngine, BlowfishTableEngine, MAX_KEY_BYTES};

trait Engine:
    BlockCipher<Error = BlockError> + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>
{
}

impl<E> Engine for E where
    E: BlockCipher<Error = BlockError> + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>
{
}

/// Runs `check` on every engine this build provides: the dispatcher, the
/// table backend and, with `rustcrypto`, the RustCrypto backend.
fn for_each_engine(check: impl Fn(&mut dyn FnMut() -> Box<dyn Engine>)) {
    check(&mut || Box::new(BlowfishEngine::new()));
    check(&mut || Box::new(BlowfishTableEngine::new()));
    #[cfg(feature = "rustcrypto")]
    check(&mut || Box::new(BlowfishRustCryptoEngine::new()));
}

fn run_vector(engine: &mut dyn Engine, key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = KeyRef::new(&key);

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = [0u8; BLOCK_BYTES];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted).unwrap(),
        BLOCK_BYTES
    );
    assert_eq!(encrypted.as_slice(), ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn all_eight_blowfish_vectors_match_in_both_directions() {
    for (key, plaintext, ciphertext) in [
        ("0000000000000000", "0000000000000000", "4EF997456198DD78"),
        ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"),
        ("3000000000000000", "1000000000000001", "7D856F9A613063F2"),
        ("1111111111111111", "1111111111111111", "2466DD878B963C9D"),
        ("0123456789ABCDEF", "1111111111111111", "61F9C3802281B096"),
        ("FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D"),
        ("7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B"),
        ("0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"),
    ] {
        for_each_engine(|new_engine| run_vector(&mut *new_engine(), key, plaintext, ciphertext));
    }
}

#[test]
fn the_maximum_length_blowfish_key_round_trips() {
    let key: Vec<u8> = (0..MAX_KEY_BYTES).map(|value| value as u8).collect();
    let params = KeyRef::new(&key);
    let plaintext = [0xA5; BLOCK_BYTES];
    for_each_engine(|new_engine| {
        let mut engine = new_engine();
        let mut ciphertext = [0u8; BLOCK_BYTES];
        let mut recovered = [0u8; BLOCK_BYTES];
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        engine.process_block(&plaintext, &mut ciphertext).unwrap();
        engine.init(CipherDirection::Decrypt, &params).unwrap();
        engine.process_block(&ciphertext, &mut recovered).unwrap();
        assert_eq!(recovered, plaintext);
    });
}
