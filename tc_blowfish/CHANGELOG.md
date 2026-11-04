# Changelog

All notable changes to `tc_blowfish` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- Blowfish single-block encryption and decryption through the
  `tc_block_cipher` traits, accepting any `KeyParams` key container. Every
  engine takes a key of 4 to 56 bytes, rejects other lengths with
  `InitError::InvalidKeyLength` while keeping its previous key, direction and
  initialization state, returns `BlockError::NotInitialised` before a key is
  installed and `BlockError::BufferTooShort` for a buffer shorter than a block
  without touching the output, and processes only the first block of a longer
  buffer.
- `BlowfishEngine`, which picks its engine at compile time: the RustCrypto
  engine with the `rustcrypto` feature, otherwise the table engine. Its type
  and API are the same under every configuration, and it has `const fn new`.
- `BlowfishTableEngine`, a portable engine on the P-array and four
  key-dependent S-boxes.
- `BlowfishRustCryptoEngine`, behind the default-off `rustcrypto` feature,
  backed by RustCrypto's `blowfish` crate with its `zeroize` feature.
- `Display` for every engine, writing `ALGO_NAME`, and the constants
  `ALGO_NAME`, `BLOCK_BYTES`, `MIN_KEY_BYTES` and `MAX_KEY_BYTES`.
- Every engine wipes its stored P-array and S-boxes on drop.
- Tests against the eight vectors of Bouncy Castle's `BlowfishTest` in both
  directions and a round trip at the longest key; a differential test against
  RustCrypto's `blowfish`; contract tests of error state, untouched output and
  preserved output tails for the dispatcher and each engine; a test that every
  engine API documents whether it is constant or variable time; and doctests
  for the engines.

### Compatibility

- Requires Rust 1.85 or later for the default build and uses Rust edition
  2024. The `rustcrypto` feature follows the minimum Rust version of the
  `blowfish` crate, which is 1.85 for `blowfish` 0.10.0; a later `blowfish`
  release may raise it without a `tc_blowfish` release.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1, and on `blowfish`
  0.10 only with `rustcrypto`.
- Every engine is variable time: key expansion fills the S-boxes from the key,
  and block processing looks them up with secret data. The crate provides no
  constant-time engine.
- Wiping reaches only the engines' stored P-array and S-boxes, not the caller's
  key buffer or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
