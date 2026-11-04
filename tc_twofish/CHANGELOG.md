# Changelog

All notable changes to `tc_twofish` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- Twofish single-block encryption and decryption through the
  `tc_block_cipher` traits as `TwofishEngine`, accepting any `KeyParams` key
  container. The engine takes a 16-, 24- or 32-byte key, rejects other lengths
  with `InitError::InvalidKeyLength` while keeping its previous key, direction
  and initialization state, returns `BlockError::NotInitialised` before a key
  is installed and `BlockError::BufferTooShort` for a buffer shorter than a
  block without touching the output, and processes only the first block of a
  longer buffer.
- `Display` for the engine, writing `ALGO_NAME`, and the constants
  `ALGO_NAME`, `BLOCK_BYTES` and `KEY_BYTES`. The engine implements `Default`
  and has `const fn new`.
- The engine wipes its stored tables and subkeys when they are replaced and on
  drop.
- Tests against the vectors of Bouncy Castle's `TwofishTest` for every key
  length in both directions and the published all-zero vector; a differential
  test against RustCrypto's `twofish`; contract tests of error state,
  untouched output and preserved output tails; a test that every engine API
  documents whether it is constant or variable time; and a doctest for the
  engine.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1.
- The engine is variable time: block processing looks up key-dependent S-box
  and MDS tables with secret data, and key setup branches on secret data. The
  crate provides no constant-time engine.
- Wiping reaches only the engine's stored tables and subkeys, not the caller's
  key buffer or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
