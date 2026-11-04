# tc_blowfish

[![crates.io](https://img.shields.io/crates/v/tc_blowfish.svg)](https://crates.io/crates/tc_blowfish)
[![docs.rs](https://docs.rs/tc_blowfish/badge.svg)](https://docs.rs/tc_blowfish)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Bruce Schneier's Blowfish block cipher, with a key of 4 to 56 bytes and a 64-bit
block, with a table engine and a dispatcher that picks an engine at compile
time. The engines implement the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `BlowfishEngine` — Blowfish on the RustCrypto engine with `rustcrypto`,
  otherwise on the table engine; variable time.
- `BlowfishTableEngine` — the P-array and four key-dependent S-boxes; variable
  time.
- `BlowfishRustCryptoEngine` (`rustcrypto`) — RustCrypto's `blowfish`;
  variable time.

Every engine takes a key of 4 to 56 bytes. Another length returns
`InitError::InvalidKeyLength` and keeps the previous key and direction.
`process_block` transforms the first 8 bytes and returns 8, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort`
for a buffer shorter than a block, without touching the output. `Display`
writes `"Blowfish"` without inspecting key material.

The constants `ALGO_NAME`, `BLOCK_BYTES`, `MIN_KEY_BYTES` and `MAX_KEY_BYTES`
hold the name, the block length, `8`, and the shortest and longest keys, `4`
and `56`. Every engine implements `Default` and has `const fn new`.

## Features

- `rustcrypto` (off by default) — adds `BlowfishRustCryptoEngine`, which
  `BlowfishEngine` then uses; pulls in the `blowfish` crate, with its `zeroize`
  feature, and its minimum Rust version.

## Usage

```toml
[dependencies]
tc_blowfish = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_blowfish::BlowfishEngine;

let key = [0x42; 16];
let mut engine = BlowfishEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("Blowfish accepts a 16-byte key");
let mut ciphertext = [0; 8];
assert_eq!(engine.process_block(&[0x11; 8], &mut ciphertext), Ok(8));
```

The crate and engine documentation carry executable examples.

## Security

Every engine is variable time: key expansion fills the S-boxes from the key, and
block processing looks them up with secret data, so cache timing can leak the
key. Use them only where cache-timing leakage is outside the threat model; this
crate provides no constant-time engine, and the RustCrypto engine is no less
leaky than the table engine.

Blowfish's 64-bit block makes it unfit for large amounts of data under one key;
it is here for the formats and systems that still use it.

Each engine keeps its expanded P-array and S-boxes rather than borrowing the
caller's key, and wipes them on drop; the RustCrypto engine wipes through the
`blowfish` crate's `zeroize` feature. Wiping does not reach the caller's key
buffer or copies left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Validation

The engines are tested against the eight vectors of Bouncy Castle's
`BlowfishTest`, in both directions, and against RustCrypto's `blowfish` on the
known vector and 64 further key and block pairs. Contract tests cover error state,
untouched output on errors and preserved output tails, for the dispatcher and
for each engine. A test requires every engine API to document whether it is
constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_blowfish --locked
cargo test -p tc_blowfish --locked --all-features
cargo clippy -p tc_blowfish --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_blowfish --check
cargo doc -p tc_blowfish --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_blowfish --list --locked
cargo publish -p tc_blowfish --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
