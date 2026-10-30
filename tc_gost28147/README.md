# tc_gost28147

[![crates.io](https://img.shields.io/crates/v/tc_gost28147.svg)](https://crates.io/crates/tc_gost28147)
[![docs.rs](https://docs.rs/tc_gost28147/badge.svg)](https://docs.rs/tc_gost28147)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The GOST 28147-89 block cipher, the former Russian standard and the base of
GOST 34.11-94 hashing and the GOST 28147 MAC, with a 256-bit key, a 64-bit
block and an S-box chosen by the caller. The engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits.

The crate is `no_std`, needs no allocator by default and contains no `unsafe`
code. It depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Traits

- `Gost28147Params` — a `KeyParams` that also supplies the S-box; implement it
  to pass a key and table from your own type.

## Types

- `Gost28147Engine` — GOST 28147-89 with a 32-byte key, a 128-byte S-box and
  an 8-byte block; variable time.
- `Gost28147ParamsRef` — a borrowed key with a borrowed S-box, the default
  table unless another is given.
- `Gost28147ParamsOwned` (`alloc`) — the same, owning the key and S-box and
  wiping them on drop.

The engine takes its key and S-box through any `Gost28147Params`. The key must
be 32 bytes and the S-box 128, eight rows of sixteen nibbles; only the lengths
are checked, as in Bouncy Castle, so any table of the right length is
accepted. Another length returns `InitError::InvalidKeyLength` or
`InitError::InvalidSBoxLength` and keeps the previous key, S-box and direction.
`process_block` transforms the first block and returns its length, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort`
for a buffer shorter than a block, without touching the output. `Display`
writes `"Gost28147"` without inspecting key material.

The `s_box` module holds the named tables of Bouncy Castle: `DEFAULT` (also
`D_TEST`), `E_TEST`, the CryptoPro encryption tables `E_A` to `E_D` and the
CryptoPro digest table `D_A` of RFC 4357, with the table dimensions `ROWS`,
`COLUMNS` and `BYTES`. The constants `BLOCK_BYTES` and `KEY_BYTES` give the
block and key lengths, and `ALGO_NAME` holds the name. The engine implements
`Default` and has `const fn new`.

## Features

- `alloc` (off by default) — adds `Gost28147ParamsOwned`.

## Usage

```toml
[dependencies]
tc_gost28147 = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_gost28147::{Gost28147Engine, Gost28147ParamsRef, s_box};

let key = [0x42; 32];
let mut engine = Gost28147Engine::new();
engine
    .init(CipherDirection::Encrypt, &Gost28147ParamsRef::with_s_box(&key, &s_box::E_A))
    .expect("GOST 28147 accepts a 32-byte key and a 128-byte S-box");
let mut ciphertext = [0; 8];
assert_eq!(engine.process_block(&[0x11; 8], &mut ciphertext), Ok(8));
```

The crate and engine documentation carry executable examples.

## Security

The engine is variable time: every round looks up the S-box with secret
nibbles, so cache timing can leak the key. Use it only where cache-timing
leakage is outside the threat model; this crate provides no constant-time
engine.

The engine keeps the key words and a copy of the S-box rather than borrowing
the caller's, and wipes them when they are replaced and on drop; some profiles
keep the S-box secret too. `Gost28147ParamsOwned` wipes its key and S-box on
drop. Wiping does not reach the caller's buffers or copies left in registers
and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication, and none of the CryptoPro key
meshing of RFC 4357.

## Validation

The engine is tested against the Bouncy Castle block and CFB-8 vectors for the
default table, the named tables and a custom table, in both directions, and
against RustCrypto's `magma` with random keys and blocks under the CryptoPro
A, B and C tables. The CryptoPro tables are checked against their RFC 4357
encodings; `magma` 0.10's CryptoPro-D table differs from the RFC, so D is not
compared with it. Contract tests cover error state, untouched output on
errors, preserved output tails and third-party parameter types. A test
requires every engine API to document whether it is constant or variable
time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_gost28147 --locked
cargo test -p tc_gost28147 --locked --all-features
cargo clippy -p tc_gost28147 --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_gost28147 --check
cargo doc -p tc_gost28147 --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_gost28147 --list --locked
cargo publish -p tc_gost28147 --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
