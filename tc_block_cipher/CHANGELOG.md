# Changelog

All notable changes to `tc_block_cipher` are documented in this file.

## 0.1.0 - 2026-09-24

Initial release.

### Added

- `BlockCipherInit<P>`, whose `init` validates and installs parameters for one
  `CipherDirection`, and `BlockCipher`, whose `block_size` and `process_block`
  transform one block. Each trait has its own associated error type, and the
  two are separate so generic callers can require exactly the capabilities they
  use. The parameter type `P` is open: a key container or an engine-specific
  type.
- `KeyParams`, which borrows key bytes and imposes no ownership or wiping
  policy, with three containers: `KeyRef` borrows a slice, `KeyFixed<N>` owns
  an array without an allocator, and `KeyOwned` takes ownership of a vector
  without cloning it. `KeyFixed` and `KeyOwned` implement `tc_zeroize::Zeroize`
  and `ZeroizeOnDrop` and wipe their storage on drop.
- `InitError` and `BlockError`, reusable `#[non_exhaustive]` error enums for
  invalid key lengths, effective key sizes, S-box and tweak lengths, round
  counts, processing before initialization, and buffers shorter than a block.
  Both implement `Display` and `core::error::Error`.
- A default-off `alloc` feature that adds `KeyOwned` through the sysroot
  `alloc` crate and enables `tc_zeroize/alloc`.
- `no_std` builds without `unsafe` code, enforced by `#![forbid(unsafe_code)]`;
  missing public documentation is rejected by `#![deny(missing_docs)]`. The
  crate documentation carries an executable example implementing both traits.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends only on `tc_zeroize` 0.1.
- The traits make no constant-time promise; key-length validation, the handling
  of buffers longer than a block, the state after a rejected initialization and
  timing are defined by each engine.
- Wiping reaches only a container's own storage, not caller-held copies, engine
  key schedules, or temporaries in registers and on the stack. Drop-based
  wiping requires the destructor to run.
- The crate supplies no mode of operation, padding or authentication.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
