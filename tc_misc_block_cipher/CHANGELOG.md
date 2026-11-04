# Changelog

All notable changes to `tc_misc_block_cipher` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- Six block ciphers ported from Bouncy Castle, one Cargo feature each, none on
  by default, each feature adding a module of the same name:
  `idea::IdeaEngine` (`idea`), `noekeon::NoekeonEngine` (`noekeon`),
  `rijndael::RijndaelEngine<BLOCK_COLUMNS>` with the aliases
  `Rijndael128Engine` to `Rijndael256Engine` (`rijndael`),
  `skipjack::SkipjackEngine` (`skipjack`), and `tea::TeaEngine` and
  `tea::XteaEngine` (`tea`).
- Every engine implements the `tc_block_cipher` traits, accepting any
  `KeyParams` key container. It rejects an unsupported key length with
  `InitError::InvalidKeyLength` while keeping its previous key, direction and
  initialization state, returns `BlockError::NotInitialised` before a key is
  installed and `BlockError::BufferTooShort` for a buffer shorter than a block
  without touching the output, and processes only the first block of a longer
  buffer.
- `Display` for every engine, writing the algorithm name, and constants in each
  module for its name, block length and key lengths. Every engine implements
  `Default` and has `const fn new`. `RijndaelEngine` rejects a block width
  outside `4..=8` columns at compile time.
- Every engine wipes its stored schedule when it is replaced and on drop.
- Tests against the vectors of Bouncy Castle's `IDEATest`, `NoekeonTest`,
  `RijndaelTest`, `SkipjackTest`, `TEATest` and `XTEATest` in both directions;
  differential tests against RustCrypto's `idea`, `aes` and `xtea`; contract
  tests of error state, untouched output and preserved output tails for each
  engine; a test for each feature that every engine API documents whether it is
  constant or variable time; and doctests for the crate and the engines.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1. No feature adds a
  dependency.
- Noekeon, TEA and XTEA are constant time with respect to key and block
  contents. IDEA, Rijndael and SKIPJACK are variable time: IDEA's multiplication
  branches on secret values and its decryption key setup runs a key-dependent
  Euclidean loop, Rijndael and SKIPJACK look up tables with secret data, and
  Rijndael's field multiplication branches on it.
- Wiping reaches only the engines' stored schedules, not the caller's key buffer
  or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
