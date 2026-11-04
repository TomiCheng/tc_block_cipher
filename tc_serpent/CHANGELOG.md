# Changelog

All notable changes to `tc_serpent` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- Serpent and Tnepres single-block encryption and decryption through the
  `tc_block_cipher` traits as `SerpentEngine` and `TnepresEngine`, accepting any
  `KeyParams` key container. Each engine takes a key of 4 to 32 bytes in
  four-byte steps, rejects other lengths with `InitError::InvalidKeyLength`
  while keeping its previous key, direction and initialization state, returns
  `BlockError::NotInitialised` before a key is installed and
  `BlockError::BufferTooShort` for a buffer shorter than a block without
  touching the output, and processes only the first block of a longer buffer.
- `Display` for each engine, writing its name, and the constants `BLOCK_BYTES`,
  `MIN_KEY_BYTES`, `MAX_KEY_BYTES`, `KEY_STEP_BYTES`, `SERPENT_ALGO_NAME` and
  `TNEPRES_ALGO_NAME`. Each engine implements `Default` and has `const fn new`.
- Each engine wipes its stored working key when it is replaced and on drop.
- Tests against the vectors of Bouncy Castle's `SerpentTest` and `TnepresTest`
  in both directions and through their hundred-iteration vectors; a differential
  test of Serpent against RustCrypto's `serpent` at each key length from 16
  bytes; contract tests of error state, untouched output and preserved output
  tails for each engine; a test that every engine API documents whether it is
  constant or variable time; and doctests for the engines.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1.
- Both engines are constant time with respect to key and block contents: the
  S-boxes are bitsliced, with Boolean operations and fixed rotations. Key
  length, representation and direction are public.
- Tnepres is a different cipher on the wire, not an alias for Serpent.
- Wiping reaches only the engines' stored working keys, not the caller's key
  buffer or copies left in registers and on the stack.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
