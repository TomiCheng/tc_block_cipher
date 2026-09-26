//! Helpers and NIST SP 800-38A AES-128 vectors shared by the mode tests.

// Each test file uses only some of these.
#![allow(dead_code)]

use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};

/// The AES-128 key shared by every mode in NIST SP 800-38A appendix F.
pub const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// The IV shared by the appendix F modes other than ECB; CTR has its own initial counter.
pub const IV: &str = "000102030405060708090a0b0c0d0e0f";
/// The four plaintext blocks shared by appendix F.
pub const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);

pub fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

/// Initializes `mode` for `direction`, processes `input` one segment at a time and returns the output.
pub fn process<M, P>(mode: &mut M, direction: CipherDirection, params: &P, input: &[u8]) -> Vec<u8>
where
    M: BlockCipher + BlockCipherInit<P>,
    P: ?Sized,
{
    mode.init(direction, params).unwrap();
    let segment = mode.block_size();
    let mut output = vec![0; input.len()];
    for (input, output) in input.chunks(segment).zip(output.chunks_mut(segment)) {
        assert_eq!(mode.process_block(input, output).unwrap(), segment);
    }
    output
}

/// Checks that encryption gives `ciphertext` and that decryption recovers `plaintext`.
pub fn assert_vectors<M, P>(mode: &mut M, params: &P, plaintext: &[u8], ciphertext: &[u8])
where
    M: BlockCipher + BlockCipherInit<P>,
    P: ?Sized,
{
    assert_eq!(
        process(mode, CipherDirection::Encrypt, params, plaintext),
        ciphertext
    );
    assert_eq!(
        process(mode, CipherDirection::Decrypt, params, ciphertext),
        plaintext
    );
}

/// Checks that an initialized mode writes only the first segment of a longer output buffer.
pub fn assert_only_the_first_segment_is_written<M: BlockCipher>(mode: &mut M) {
    let segment = mode.block_size();
    let input = [0x5a; 40];
    let mut output = [0xa5; 40];
    assert_eq!(mode.process_block(&input, &mut output).unwrap(), segment);
    assert!(output[segment..].iter().all(|&byte| byte == 0xa5));
}

/// Encrypts one block with AES directly, as a reference.
pub fn aes_encrypt_block(key: &[u8], block: &[u8]) -> [u8; 16] {
    let mut engine = AesEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(key))
        .unwrap();
    let mut output = [0; 16];
    engine.process_block(block, &mut output).unwrap();
    output
}
