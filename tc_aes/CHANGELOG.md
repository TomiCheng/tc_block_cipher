# Changelog

All notable changes to `tc_aes` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- AES-128, AES-192 and AES-256 single-block encryption and decryption through
  the `tc_block_cipher` traits, accepting any `KeyParams` key container. Every
  engine rejects key lengths other than 16, 24 and 32 bytes with
  `InitError::InvalidKeyLength` while keeping its previous key and direction,
  returns `BlockError::NotInitialised` before a key is installed and
  `BlockError::BufferTooShort` for a buffer shorter than a block, and processes
  only the first block of a longer buffer.
- `AesEngine`, which picks its engine once at construction:
  `AesRustCryptoEngine` with the `rustcrypto` feature, otherwise `AesX86Engine`
  where AES-NI is detected, and `AesTableEngine` as the last resort. Its type
  and API are the same under every configuration.
- `AesX86Engine` on x86 and x86-64, built on the AES-NI instructions behind a
  `tc_runtime` detection token. `new` returns `None` without AES-NI, and
  `is_supported` reports availability. Constant time, including a key schedule
  that computes the S-box rather than looking it up.
- `AesRustCryptoEngine`, behind the default-off `rustcrypto` feature, backed by
  RustCrypto's `aes` crate with its `zeroize` feature. Constant time on every
  backend that crate selects.
- `AesTableEngine`, a portable engine with one forward and one inverse 1 KiB
  T-table, and `AesLightEngine`, a small-footprint engine using only the
  S-boxes. Both are variable time and documented as such.
- `Display` for every engine, writing `ALGO_NAME`, and the constants
  `ALGO_NAME`, `BLOCK_BYTES` and `KEY_BYTES`.
- S-boxes computed at compile time from the GF(2^8) arithmetic, and a
  constant-time FIPS 197 key expansion shared by the AES-NI and table engines.
  Every engine wipes its stored key schedule on drop.
- Tests against the FIPS 197 Appendix C vectors for every engine, key size and
  direction; the Appendix A key expansion; cross-checks between the engines,
  and against RustCrypto, on pseudorandom keys and blocks; and doctests for the crate and every engine. Missing public documentation and
  unsafe operations outside an explicit `unsafe` block are rejected by
  crate-level lints.
- Criterion benchmarks for key setup and single-block processing on every
  available engine and the dispatcher.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024. With `rustcrypto`,
  Rust 1.85 through 1.88 need `aes` 0.9.2 or earlier, since 0.9.3 requires
  Rust 1.89; Cargo's MSRV-aware resolver selects such a release for projects
  that declare a `rust-version`.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1, on `tc_runtime` 0.1 on
  x86 and x86-64 only, and on `aes` 0.9 only with `rustcrypto`.
- Without `rustcrypto`, `AesEngine` is constant time only where AES-NI is
  available; elsewhere it falls back to the variable-time table engine.
- Wiping reaches only the engines' stored key schedules, not the caller's key
  buffer or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding, nonce management or
  authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
