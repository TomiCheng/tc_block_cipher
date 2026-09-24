# Changelog

All notable changes to `tc_des` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- DES and EDE Triple DES single-block encryption and decryption through the
  `tc_block_cipher` traits, accepting any `KeyParams` key container. DES takes
  an 8-byte encoded key; Triple DES takes 16 bytes, used as `K1, K2, K1`, or
  24 bytes. Every engine rejects other key lengths with
  `InitError::InvalidKeyLength` while keeping its previous key, direction and
  initialization state, returns `BlockError::NotInitialised` before a key is
  installed and `BlockError::BufferTooShort` for a buffer shorter than a block
  without touching the output, and processes only the first block of a longer
  buffer. Parity bits are ignored and weak keys are accepted.
- `DesEngine` and `DesEdeEngine`, which pick their engine at compile time: the
  RustCrypto engines with the `rustcrypto` feature, otherwise the table
  engines. Their types and APIs are the same under every configuration, and
  both have `const fn new`.
- `DesTableEngine` and `DesEdeTableEngine`, portable engines built on eight
  256-byte SP-box tables that combine each S-box with the P permutation.
- `DesRustCryptoEngine` and `DesEdeRustCryptoEngine`, behind the default-off
  `rustcrypto` feature, backed by RustCrypto's `des` crate with its `zeroize`
  feature. Their 64-byte S-boxes and branch-free key schedule narrow the
  cache-timing channel compared with the table engines.
- `Display` for every engine, writing `DES_ALGO_NAME` or `DES_EDE_ALGO_NAME`,
  and the constants `BLOCK_BYTES`, `DES_ALGO_NAME`, `DES_KEY_BYTES`,
  `DES_EDE_ALGO_NAME`, `DES_EDE_KEY_BYTES`, `EDE2_KEY_BYTES` and
  `EDE3_KEY_BYTES`.
- Every engine wipes its stored key schedule when it is replaced and on drop.
- Tests against the standard DES vector, the FIPS 81 vector and a weak-key
  vector, and against the two-key, three-key and NIST Triple DES vectors, in
  both directions; contract tests of error state, untouched output, preserved
  output tails and ignored parity bits for every engine; cross-checks between
  the table and RustCrypto engines on pseudorandom keys and blocks; a test that
  every engine API documents whether it is constant or variable time; and
  doctests for every engine.

### Compatibility

- Requires Rust 1.85 or later for the default build and uses Rust edition
  2024. The `rustcrypto` feature follows the minimum Rust version of the `des`
  crate, which is 1.85 for `des` 0.9.0; a later `des` release may raise it
  without a `tc_des` release.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1, and on `des` 0.9 only
  with `rustcrypto`.
- Every engine is variable time: each looks up S-boxes with secret data, and
  the table engines' key setup also branches on key bits. The crate provides no
  constant-time engine.
- DES and Triple DES are provided for legacy interoperability only and are not
  suitable for new designs.
- Wiping reaches only the engines' stored key schedules, not the caller's key
  buffer or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
