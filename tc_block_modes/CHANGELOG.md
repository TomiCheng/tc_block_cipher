# Changelog

All notable changes to `tc_block_modes` are documented in this file.

## 0.1.0 - 2026-09-26

Initial release.

### Added

- ECB, CBC, CFB, OFB and CTR modes of operation over any engine that
  implements the `tc_block_cipher` traits. Each mode is itself a
  `BlockCipher`, initialized through `BlockCipherInit` with the engine's
  parameters plus an IV provided through `IvParams`, and implements
  `BlockCipherMode` to restart from its IV and expose the wrapped engine.
- `FixedCbcBlockCipher`, `FixedCfbBlockCipher`, `FixedOfbBlockCipher` and
  `FixedCtrBlockCipher`, which take the block size, and the CFB or OFB segment
  size, as const generics and need no allocator; and `CbcBlockCipher`,
  `CfbBlockCipher`, `OfbBlockCipher` and `CtrBlockCipher` behind the default-off
  `alloc` feature, which size their state from the engine at runtime.
  `EcbBlockCipher` forwards to the engine unchanged.
- CBC takes an IV of exactly one block. CFB and OFB take up to one block and
  right-align a shorter IV over zeros, as in FIPS 81, with feedback sizes from
  8 bits to one block. CTR fills the leading bytes of its counter block with
  the IV, may leave at most `min(8, block / 2)` bytes of counter, and increments
  the whole block without branching.
- A rejected `init` keeps the previous IV and chaining state. `process_block`
  transforms only the first segment of a longer buffer, and returns
  `BlockModeError::NotInitialised` before `init` and `BufferTooShort` for a
  short buffer without changing the mode.
- `KeyWithIvRef`, `KeyWithIvFixed` and, with `alloc`, `KeyWithIvOwned`
  parameter containers. The owning forms wipe the key and the IV on drop, and
  `Debug` writes only the lengths.
- `BlockModeError` and `BlockModeInitError`, which wrap the engine's errors.
- `Display` for every mode, writing the engine's name followed by `/ECB`,
  `/CBC`, `/CFB` or `/OFB` with the segment size in bits, or `/CTR`.
- Every stateful mode wipes its IV, its feedback register or counter, and its
  last chaining or keystream block on drop.
- Tests against the NIST SP 800-38A AES-128 vectors for every mode, including
  CFB8, in both directions and in both the fixed-size and runtime-sized forms;
  contract tests of the IV rules, the CTR counter carry, feedback-size
  validation, reset, direction handling, state kept across a rejected `init`,
  short-buffer errors and preserved output tails; a test that every public API
  documents whether it is constant or variable time; and doctests for every
  public type.

### Compatibility

- Requires Rust 1.85 or later, with or without `alloc`, and uses Rust edition
  2024.
- Depends on `tc_block_cipher` 0.1 and `tc_zeroize` 0.1.
- The modes add only data-independent work: each call is constant time exactly
  when the engine is.
- No mode authenticates, and none pads; ECB and CBC take whole blocks only.
- Wiping does not reach the caller's buffers or copies left in registers and on
  the stack.
- OpenPGP CFB, GOFB, KCTR and a byte-oriented stream interface for CTR are not
  provided.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
