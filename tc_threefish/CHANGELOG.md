# Changelog

All notable changes to `tc_threefish` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- Threefish single-block encryption and decryption through the
  `tc_block_cipher` traits: `Threefish256Engine`, `Threefish512Engine` and
  `Threefish1024Engine`, as aliases of `ThreefishEngine`, which picks its
  engine at compile time: `ThreefishRustCryptoEngine` with the `rustcrypto`
  feature, otherwise `ThreefishPortableEngine`. Its type and API are the same
  under every configuration.
- `ThreefishPortableEngine`, after Bouncy Castle's `ThreefishEngine`, with one
  round function per block width unrolled to eight rounds per iteration and
  subkeys derived while each block is processed, so `init` stays cheap; and
  `ThreefishRustCryptoEngine`, behind the default-off `rustcrypto` feature,
  backed by RustCrypto's `threefish` crate with its `zeroize` feature, which
  expands every subkey in `init`.
- Each engine type's const parameter counts 64-bit block words, and only 4, 8
  and 16 compile. Each engine takes a block-sized key and an
  optional 16-byte tweak, an absent tweak being all zero, and rejects other
  lengths with `InitError::InvalidKeyLength` or `InitError::InvalidTweakLength`
  while keeping its previous key, tweak, direction and initialization state. It
  returns `BlockError::NotInitialised` before a key is installed and
  `BlockError::BufferTooShort` for a buffer shorter than a block without
  touching the output, and processes only the first block of a longer buffer.
- `ThreefishParams`, a `KeyParams` that also supplies the tweak;
  `ThreefishParamsRef`, a borrowed key with an optional borrowed tweak; and
  `ThreefishParamsOwned`, behind the default-off `alloc` feature, which owns
  the key and tweak and wipes them on drop. `Debug` on both parameter types
  prints the lengths, never the key or tweak.
- `Display` for every engine, writing its variant name, and the constants
  `TWEAK_BYTES`, `THREEFISH_256_ALGO_NAME`, `THREEFISH_512_ALGO_NAME` and
  `THREEFISH_1024_ALGO_NAME`. Every engine implements `Default` and has
  `const fn new`.
- Every engine wipes its stored key and tweak, or expanded schedule, when they
  are replaced and on drop.
- Tests of every engine against the Skein 1.3 and Bouncy Castle vectors for
  every block size in both directions and against RustCrypto's `threefish` with
  random keys, tweaks and blocks; contract tests of error state, untouched
  output, preserved output tails, absent tweaks and third-party parameter
  types for every engine; a test that every engine API documents whether it is
  constant or variable time; and doctests for every engine and the owned
  parameter type.

### Compatibility

- Requires Rust 1.85 or later for the default build and the `alloc` feature,
  and uses Rust edition 2024. The `rustcrypto` feature follows the minimum Rust
  version of the `threefish` crate, which is 1.85 for `threefish` 0.6.0; a
  later `threefish` release may raise it without a `tc_threefish` release.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1, and on `threefish` 0.6
  only with `rustcrypto`.
- Every engine is constant time with respect to the key, the tweak and the
  block contents.
- Wiping reaches only the engines' stored key and tweak or schedule and the key
  and tweak of `ThreefishParamsOwned`, not the caller's buffers or copies left
  in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
