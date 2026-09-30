# Changelog

All notable changes to `tc_dstu7624` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- DSTU 7624:2014 (Kalyna) single-block encryption and decryption through the
  `tc_block_cipher` traits, accepting any `KeyParams` key container:
  `Dstu7624Engine128` with a 128- or 256-bit key, `Dstu7624Engine256` with a
  256- or 512-bit key, and `Dstu7624Engine512` with a 512-bit key, as aliases
  of `Dstu7624Engine`, whose const parameter counts 64-bit block words. Every
  engine rejects other key lengths with `InitError::InvalidKeyLength` while
  keeping its previous key, direction and initialization state, returns
  `BlockError::NotInitialised` before a key is installed and
  `BlockError::BufferTooShort` for a buffer shorter than a block without
  touching the output, and processes only the first block of a longer buffer.
- `Display` for every engine, writing `ALGO_NAME`, and the constants
  `ALGO_NAME`, `BLOCK_BITS` and `KEY_BYTES`. Every engine implements `Default`
  and has `const fn new`.
- Every engine wipes its stored key schedule when it is replaced and on drop.
- Tests against the Bouncy Castle ECB vectors for every block and key size in
  both directions; contract tests of error state, untouched output and
  preserved output tails; a test that every engine API documents whether it is
  constant or variable time; and doctests for the engines.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1.
- Every engine is variable time: key setup and block processing look up
  S-boxes with secret data. The crate provides no constant-time engine.
- Wiping reaches only the engines' stored key schedules, not the caller's key
  buffer or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
