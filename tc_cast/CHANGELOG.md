# Changelog

All notable changes to `tc_cast` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- CAST5 (RFC 2144) and CAST6 (RFC 2612) single-block encryption and
  decryption through the `tc_block_cipher` traits as `Cast5Engine` and
  `Cast6Engine`, accepting any `KeyParams` key container. CAST5 takes a 5- to
  16-byte key and CAST6 a 16-, 20-, 24-, 28- or 32-byte key. Each engine
  rejects another key length with `InitError::InvalidKeyLength` while keeping
  its previous key, direction and initialization state, returns
  `BlockError::NotInitialised` before a key is installed and
  `BlockError::BufferTooShort` for a buffer shorter than a block without
  touching the output, and processes only the first block of a longer buffer.
- `Display` for each engine, writing its `ALGO_NAME`, and the constants of the
  `cast5` and `cast6` modules: `BLOCK_BYTES`, `ALGO_NAME` and the key lengths.
  Each engine implements `Default` and has `const fn new`.
- Each engine wipes its stored key schedule when it is replaced and on drop.
- Tests against the RFC 2144 and RFC 2612 vectors of Bouncy Castle's
  `Cast5Test` and `CAST6Test`, in both directions; a differential test against
  RustCrypto's `cast5` and `cast6` at every key length; contract tests of
  error state, untouched output and preserved output tails; a test that every
  engine API documents whether it is constant or variable time; and doctests
  for the engines.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1.
- Both engines are variable time: key setup and block processing look up
  their S-boxes with secret data. The crate provides no constant-time engine.
- Wiping reaches only the engines' stored key schedules, not the caller's key
  buffer or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
