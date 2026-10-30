# Changelog

All notable changes to `tc_threefish` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- Threefish single-block encryption and decryption through the
  `tc_block_cipher` traits: `Threefish256Engine`, `Threefish512Engine` and
  `Threefish1024Engine`, as aliases of `ThreefishEngine`, whose const parameter
  counts 64-bit block words. Each engine takes a block-sized key and an
  optional 16-byte tweak, an absent tweak being all zero, and rejects other
  lengths with `InitError::InvalidKeyLength` or `InitError::InvalidTweakLength`
  while keeping its previous key, tweak, direction and initialization state. It
  returns `BlockError::NotInitialised` before a key is installed and
  `BlockError::BufferTooShort` for a buffer shorter than a block without
  touching the output, and processes only the first block of a longer buffer.
- `ThreefishParams`, a `KeyParams` that also supplies the tweak, and
  `ThreefishParamsRef`, a borrowed key with an optional borrowed tweak.
- `Display` for every engine, writing its variant name, and the constants
  `TWEAK_BYTES`, `THREEFISH_256_ALGO_NAME`, `THREEFISH_512_ALGO_NAME` and
  `THREEFISH_1024_ALGO_NAME`. Every engine implements `Default` and has
  `const fn new`.
- Every engine wipes its stored key and tweak when they are replaced and on
  drop.
- Tests against the Skein 1.3 and Bouncy Castle vectors for every block size in
  both directions; a differential test against RustCrypto's `threefish`;
  contract tests of error state, untouched output, preserved output tails,
  absent tweaks and third-party parameter types; a test that every engine API
  documents whether it is constant or variable time; and doctests for the
  engines.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1.
- Every engine is constant time with respect to the key, the tweak and the
  block contents.
- Wiping reaches only the engines' stored key and tweak, not the caller's
  buffers or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
