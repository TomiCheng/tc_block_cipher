# tc_des

[![crates.io](https://img.shields.io/crates/v/tc_des.svg)](https://crates.io/crates/tc_des)
[![docs.rs](https://docs.rs/tc_des/badge.svg)](https://docs.rs/tc_des)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

DES and EDE Triple DES block ciphers for legacy interoperability, with
table-based and RustCrypto engines. Every engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, and a
dispatcher for each algorithm picks the less leaky engine the build provides.
Do not use DES or Triple DES in new designs.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and [`tc_zeroize`](https://crates.io/crates/tc_zeroize),
and on RustCrypto's [`des`](https://crates.io/crates/des) only with the
default-off `rustcrypto` feature.

Requires Rust 1.85 or later (edition 2024) for the default build. The optional
`rustcrypto` feature follows the minimum Rust version of the `des` crate
instead, which is 1.85 for `des` 0.9.0.

## Types

- `DesEngine` — DES on the RustCrypto engine with `rustcrypto`, otherwise on
  the table engine; variable time.
- `DesEdeEngine` — Triple DES, chosen the same way; variable time.
- `DesTableEngine`, `DesEdeTableEngine` — portable SP-box tables; variable
  time, with key setup that also branches on key bits.
- `DesRustCryptoEngine`, `DesEdeRustCryptoEngine` (`rustcrypto`) —
  RustCrypto's `des`; variable time, with smaller S-boxes and a branch-free key
  schedule.

DES takes an 8-byte encoded key; Triple DES takes 16 bytes, used as
`K1, K2, K1`, or 24 bytes. Another length returns `InitError::InvalidKeyLength`
and keeps the previous key. `process_block` transforms the first 8 bytes and
returns 8, returning `BlockError::NotInitialised` before `init` and
`BlockError::BufferTooShort` for a buffer shorter than a block, without
touching the output. Parity bits are ignored and weak keys are accepted.
`Display` writes `"DES"` or `"DESede"` without inspecting key material.

The constants `DES_ALGO_NAME` and `DES_EDE_ALGO_NAME` hold the two names,
`DES_KEY_BYTES` and `DES_EDE_KEY_BYTES` the accepted key lengths, `[8]` and
`[16, 24]`, `EDE2_KEY_BYTES` and `EDE3_KEY_BYTES` the two Triple DES lengths,
and `BLOCK_BYTES` the block length, `8`. Every engine implements `Default` and
has `const fn new`.

## Features

- `rustcrypto` (off by default) — adds the two RustCrypto engines, which the
  dispatchers then always use; pulls in the `des` crate and its minimum Rust
  version.

## Usage

```toml
[dependencies]
tc_des = "0.1.0"
tc_block_cipher = "0.1.0"
```

This example uses the NIST three-key Triple DES vector:

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_des::{BLOCK_BYTES, DesEdeEngine};

let key = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
];
let plaintext = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

let mut engine = DesEdeEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("Triple DES accepts a 24-byte key");
let mut ciphertext = [0; BLOCK_BYTES];
assert_eq!(engine.process_block(&plaintext, &mut ciphertext), Ok(BLOCK_BYTES));
assert_eq!(ciphertext, [0x07, 0x37, 0xf6, 0xc5, 0x37, 0x50, 0xd4, 0xa4]);
```

The crate and engine documentation carry executable examples for every engine.

## Security

Every engine is variable time. Each looks up S-boxes with secret data, so
cache timing can leak the key, and the table engines' key setup also branches
on key bits. The RustCrypto engines narrow that channel but do not close it;
this crate provides no constant-time engine. Use it only where cache-timing
leakage is outside the threat model.

Engines keep an expanded key schedule rather than borrowing the caller's key,
and wipe it when it is replaced and on drop. Wiping does not reach the caller's
key buffer or copies left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Validation

The engines are tested against the standard DES vector, the FIPS 81 vector and
a weak-key vector, and against the two-key, three-key and NIST Triple DES
vectors, in both directions. Contract tests cover error state, untouched output
on errors, preserved output tails and ignored parity bits for every engine.
With `rustcrypto`, the table engines are cross-checked against RustCrypto's
`des` on pseudorandom keys and blocks, and the RustCrypto engines against the
table engines. A test requires every engine API to document whether it is
constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_des --locked
cargo test -p tc_des --locked --features rustcrypto
cargo clippy -p tc_des --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_des --check
cargo doc -p tc_des --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_des --list --locked
cargo publish -p tc_des --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
source and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
