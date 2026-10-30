# Changelog

All notable changes to `tc_gost28147` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- GOST 28147-89 single-block encryption and decryption through the
  `tc_block_cipher` traits as `Gost28147Engine`, with a 32-byte key, a
  128-byte S-box and an 8-byte block. The engine checks only the key and
  S-box lengths, rejecting others with `InitError::InvalidKeyLength` or
  `InitError::InvalidSBoxLength` while keeping its previous key, S-box,
  direction and initialization state. It returns `BlockError::NotInitialised`
  before a key is installed and `BlockError::BufferTooShort` for a buffer
  shorter than a block without touching the output, and processes only the
  first block of a longer buffer.
- `Gost28147Params`, a `KeyParams` that also supplies the S-box;
  `Gost28147ParamsRef`, a borrowed key with a borrowed S-box that defaults to
  `s_box::DEFAULT`; and `Gost28147ParamsOwned`, behind the default-off `alloc`
  feature, which owns the key and S-box and wipes them on drop. `Debug` on
  both parameter types prints the lengths, never the key or table.
- The `s_box` module with Bouncy Castle's named tables: `DEFAULT` and its
  alias `D_TEST`, `E_TEST`, the CryptoPro encryption tables `E_A`, `E_B`,
  `E_C` and `E_D` and the CryptoPro digest table `D_A`, and the dimensions
  `ROWS`, `COLUMNS` and `BYTES`.
- `Display` for the engine, writing `ALGO_NAME`, and the constants
  `ALGO_NAME`, `BLOCK_BYTES` and `KEY_BYTES`. The engine implements `Default`
  and has `const fn new`.
- The engine wipes its stored key words and S-box when they are replaced and
  on drop.
- Tests against the Bouncy Castle block and CFB-8 vectors for the default,
  named and custom tables in both directions; a differential test against
  RustCrypto's `magma` under the CryptoPro A, B and C tables; a check of the
  CryptoPro tables against their RFC 4357 encodings; contract tests of error
  state, untouched output, preserved output tails and third-party parameter
  types; a test that every engine API documents whether it is constant or
  variable time; and doctests for the engine and parameter types.

### Compatibility

- Requires Rust 1.85 or later for the default build and the `alloc` feature,
  and uses Rust edition 2024.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1.
- The engine is variable time: every round looks up the S-box with secret
  nibbles. The crate provides no constant-time engine.
- Wiping reaches only the engine's stored key words and S-box and the key and
  S-box of `Gost28147ParamsOwned`, not the caller's buffers or copies left in
  registers and on the stack.
- The crate supplies no mode of operation, padding, authentication or
  CryptoPro key meshing.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
