# Changelog

All notable changes to `tc_rc_cipher` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- RC2, RC5 and RC6 single-block encryption and decryption through the
  `tc_block_cipher` traits. RC2 takes a 1- to 128-byte key and an effective key
  size of 1 to 1024 bits; RC5 a 1- to 255-byte key and 0 to 255 rounds; RC6 a
  1- to 255-byte key. Every engine rejects invalid parameters with
  `InitError::InvalidKeyLength`, `InvalidEffectiveKeyBits` or `InvalidRounds`
  while keeping its previous key, direction and initialization state, returns
  `BlockError::NotInitialised` before a key is installed and
  `BlockError::BufferTooShort` for a buffer shorter than a block without
  touching the output, and processes only the first block of a longer buffer.
- `Rc2Engine`, which picks its engine at compile time: `Rc2RustCryptoEngine`
  with the `rustcrypto` feature, otherwise `Rc2TableEngine`. Its type and API
  are the same under every configuration.
- `Rc2TableEngine`, a portable RC2 engine, and `Rc2RustCryptoEngine`, behind
  the default-off `rustcrypto` feature, backed by RustCrypto's `rc2` crate with
  its `zeroize` feature.
- `Rc532Engine` and `Rc564Engine`, RC5 with 32- and 64-bit words and 8- and
  16-byte blocks, and `Rc6Engine`, RC6-32/20 with a 16-byte block.
- The `Rc2Params` and `Rc5Params` traits, which supply a key with its RC2
  effective size or RC5 round count; `Rc2ParamsRef` and `Rc5ParamsRef`, which
  borrow the key; and `Rc2ParamsOwned` and `Rc5ParamsOwned`, behind the
  default-off `alloc` feature, which own the key and wipe it on drop. `Debug`
  on every parameter type prints the key length, never the key.
- `Display` for every engine, writing `"RC2"`, `"RC5-32"`, `"RC5-64"` or
  `"RC6"`, and constants for the names and limits of each algorithm:
  `RC2_ALGO_NAME`, `RC2_BLOCK_BYTES`, `RC2_MAX_KEY_BYTES`,
  `RC2_MAX_EFFECTIVE_KEY_BITS`, `RC5_32_ALGO_NAME`, `RC5_64_ALGO_NAME`,
  `RC5_32_BLOCK_BYTES`, `RC5_64_BLOCK_BYTES`, `RC5_DEFAULT_ROUNDS`,
  `RC5_MAX_ROUNDS`, `RC5_MAX_KEY_BYTES`, `RC6_ALGO_NAME`, `RC6_BLOCK_BYTES`,
  `RC6_ROUNDS` and `RC6_MAX_KEY_BYTES`.
- Every engine wipes its stored key schedule when it is replaced and on drop.
- Tests against RFC 2268 and Bouncy Castle RC2 vectors, RFC 2040 and Bouncy
  Castle RC5 vectors, and AES-submission and Bouncy Castle RC6 vectors, in both
  directions; contract tests of error state, untouched output, preserved output
  tails and dynamic dispatch for every engine; a cross-check of the RustCrypto
  RC2 engine against the table engine; a test that every engine API documents
  whether it is constant or variable time; and doctests for every engine and
  parameter type.

### Compatibility

- Requires Rust 1.85 or later for the default build and the `alloc` feature,
  and uses Rust edition 2024. The `rustcrypto` feature follows the minimum Rust
  version of the `rc2` crate, which is 1.85 for `rc2` 0.9.0; a later `rc2`
  release may raise it without a `tc_rc_cipher` release.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1, and on `rc2` 0.9 only
  with `rustcrypto`.
- Every RC2 engine is variable time: key setup indexes the PI table with key
  bytes and every block indexes the expanded key with block data. RC5 and RC6
  are constant time only on processors with fixed-latency data-dependent
  rotations and, for RC6, 32-bit multiplication.
- RC2, RC5 and RC6 are provided for interoperability with existing formats and
  are not suitable for new designs.
- Wiping reaches only the engines' stored key schedules and the owned parameter
  types' keys, not the caller's key buffer or copies left in registers and on
  the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
