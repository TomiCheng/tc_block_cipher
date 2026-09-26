# Changelog

All notable changes to `tc_aria` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- ARIA-128, ARIA-192 and ARIA-256 single-block encryption and decryption, as
  specified by RFC 5794, through the `tc_block_cipher` traits, accepting any
  `KeyParams` key container. Every engine takes a 16-, 24- or 32-byte key,
  rejects other lengths with `InitError::InvalidKeyLength` while keeping its
  previous key and direction, returns `BlockError::NotInitialised` before a key
  is installed and `BlockError::BufferTooShort` for a buffer shorter than a
  block without touching the output, and processes only the first block of a
  longer buffer.
- `AriaEngine`, which picks its engine at compile time: the RustCrypto engine
  with the `rustcrypto` feature, otherwise the table engine. Its type and API
  are the same under every configuration, and it has `const fn new`.
- `AriaTableEngine`, a portable engine built on the four ARIA S-boxes.
- `AriaRustCryptoEngine`, behind the default-off `rustcrypto` feature, backed
  by RustCrypto's `aria` crate with its `zeroize` feature.
- `Display` for every engine, writing `ALGO_NAME`, and the constants
  `ALGO_NAME`, `BLOCK_BYTES` and `KEY_BYTES`.
- Every engine wipes its stored key schedule on drop.
- Tests against the RFC 5794 vectors for all three key sizes in both
  directions; contract tests of error state, untouched output, single-block
  processing and `Display` for every engine; cross-checks between the table
  and RustCrypto engines on pseudorandom keys and blocks; a test that every
  engine API documents whether it is constant or variable time; and doctests
  for every engine.
- Criterion benchmarks for key setup and single-block processing on the table
  and RustCrypto engines, with results in `BENCHES.md`.

### Compatibility

- Requires Rust 1.85 or later for the default build and uses Rust edition
  2024. The `rustcrypto` feature follows the minimum Rust version of the `aria`
  crate, which is 1.85 for `aria` 0.2.0; a later `aria` release may raise it
  without a `tc_aria` release.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1, and on `aria` 0.2 only
  with `rustcrypto`.
- Every engine is variable time: each looks up S-boxes with secret data during
  key setup and block processing. The crate provides no constant-time engine.
- Wiping reaches only the engines' stored key schedules, not the caller's key
  buffer or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
