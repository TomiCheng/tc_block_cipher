# Changelog

All notable changes to `tc_block_modes` are documented in this file.

## 0.1.2 - 2026-11-14

### Added

- `ParamsWithIvRef<'a, TParams: ?Sized>`, an engine's own parameters and an
  IV, both borrowed, and `ParamsWithIvOwned<TParams>` (`alloc`), which owns
  them, as Bouncy Castle's `ParametersWithIV`. Every mode with an IV, CBC, CFB,
  OFB, CTR, OpenPGP CFB, GOFB and KCTR, in its fixed and runtime-sized forms,
  implements `BlockCipherInit` for both, for any engine that implements
  `BlockCipherInit<TParams>`: it checks and keeps the IV as before and
  initializes the engine with the inner parameters alone. `ParamsWithIvRef`
  needs no allocator, so the fixed-size modes take it without `alloc`, and its
  `TParams` may be a trait object. An
  engine whose parameters are more than a key, such as RC2 with its effective
  key bits, RC5 with its rounds or GOST 28147 with its S-box, can now be used
  in these modes; before, only the `KeyWithIv` types and parameter types that
  implement both the engine's trait and `IvParams` could. `ParamsWithIvOwned`
  wipes the IV on drop and, with `TParams: Zeroize`, both on `zeroize`;
  `ParamsWithIvRef` leaves wiping to the owner, as `KeyWithIvRef` does.
- Tests that a bare key in either gives the same output as the matching
  `KeyWithIv` type in every mode, of RC2 in CBC with 40 effective key bits
  against CBC done by hand over the engine, also behind `dyn Rc2Params` and in
  a fixed-size mode without `alloc`, of GOST 28147 in GOFB with its S-box
  against Bouncy Castle's vector, and of the IV lengths each mode refuses.
- `tc_rc_cipher` as a dev-dependency for those tests, and the `alloc` features
  of `tc_block_cipher` and `tc_gost28147` for them.

### Compatibility

- Additive only: no existing API changes. Neither type implements
  `IvParams`, so their implementations do not overlap those over `IvParams`.
- Each mode's `init` now runs through one private helper shared by both
  implementations; its checks, errors and state kept across a rejected `init`
  are unchanged.

## 0.1.1 - 2026-10-30

### Added

- The algorithm-specific modes that 0.1.0 left out, after Bouncy Castle:
  `FixedOpenPgpCfbBlockCipher` and `OpenPgpCfbBlockCipher` (`alloc`), OpenPGP's
  CFB variant of RFC 4880 that resynchronizes after the first block and two
  bytes; `GofbBlockCipher`, GOST 28147-89 counter mode (GCTR) over an 8-byte
  block; and `FixedKctrBlockCipher` and `KctrBlockCipher` (`alloc`), DSTU 7624
  counter mode (KCTR). `Display` appends `/OpenPGPCFB`, `/GCTR` and `/KCTR`.
- Tests of GOFB against Bouncy Castle's GOST 28147 vectors with the default
  and a custom S-box and over 4096 blocks through its counter fix-up; of KCTR
  against Bouncy Castle's DSTU 7624 vectors, a final partial block, a 256-bit
  block and 1024 blocks of counter carries; and of OpenPGP CFB against vectors
  produced by Bouncy Castle's `OpenPgpCfbBlockCipher` for AES and GOST 28147.
  Contract tests cover their IV rules, reset, direction handling, state kept
  across a rejected `init` and errors.
- `tc_gost28147` and `tc_dstu7624` as dev-dependencies for those tests.

### Compatibility

- Additive only: no existing API changes.
- Like the other modes, the new ones take an IV of at most one block,
  right-aligned over zeros, and reject a longer one; Bouncy Castle truncates
  it.
- GOFB applies Bouncy Castle's fix-up to its high counter word, its
  approximation of addition modulo `2^32 - 1`, without branching on the
  counter. KCTR increments its counter without branching. Each new mode is
  constant time exactly when its engine is.
- KCTR seeds its counter by encrypting the IV on the first block after `init`
  or `reset`, where Bouncy Castle does it inside `Init`; the keystream is the
  same.
- As for CTR, no byte-oriented stream interface is provided for KCTR.

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
