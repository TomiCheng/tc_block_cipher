# tc_cast

[![crates.io](https://img.shields.io/crates/v/tc_cast.svg)](https://crates.io/crates/tc_cast)
[![docs.rs](https://docs.rs/tc_cast/badge.svg)](https://docs.rs/tc_cast)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The CAST5 block cipher of RFC 2144, also known as CAST-128, with a 64-bit block,
and its AES candidate successor CAST6 of RFC 2612, also known as CAST-256, with a
128-bit block. The engines implement the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `Cast5Engine` — CAST5 with a 5- to 16-byte key and an 8-byte block; variable time.
- `Cast6Engine` — CAST6 with a 16-, 20-, 24-, 28- or 32-byte key and a 16-byte block; variable time.

Each engine takes its key through any `KeyParams`, such as `KeyRef`. A key
length the cipher does not take returns `InitError::InvalidKeyLength` and keeps
the previous key. `process_block` transforms the first block and returns its
length, returning `BlockError::NotInitialised` before `init` and
`BlockError::BufferTooShort` for a buffer shorter than a block, without
touching the output. `Display` writes `"CAST5"` or `"CAST6"` without
inspecting key material.

The `cast5` module holds `BLOCK_BYTES`, `MIN_KEY_BYTES`, `MAX_KEY_BYTES` and
`ALGO_NAME`, and the `cast6` module `BLOCK_BYTES`, `KEY_BYTES`, the five key
lengths, and `ALGO_NAME`. Each engine implements `Default` and has
`const fn new`.

## Usage

```toml
[dependencies]
tc_cast = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_cast::Cast5Engine;

let key = [0x42; 16];
let mut engine = Cast5Engine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("CAST5 accepts a 16-byte key");
let mut ciphertext = [0; 8];
assert_eq!(engine.process_block(&[0x11; 8], &mut ciphertext), Ok(8));
```

The crate and engine documentation carry executable examples.

## Security

Both engines are variable time: key setup and block processing look up their
S-boxes with secret data, so cache timing can leak the key. Use them only where
cache-timing leakage is outside the threat model; this crate provides no
constant-time engine.

CAST5's 64-bit block makes it unfit for large amounts of data under one key; it
is here for OpenPGP and other formats that name it.

Each engine keeps an expanded key schedule rather than borrowing the caller's
key, and wipes it when it is replaced and on drop. Wiping does not reach the
caller's key buffer or copies left in registers and on the stack.

These are block-cipher primitives, not a message-encryption format. They supply
no padding, mode of operation or authentication.

## Validation

The engines are tested against the vectors of RFC 2144 and RFC 2612 that Bouncy
Castle's `Cast5Test` and `CAST6Test` use, in both directions, and against
RustCrypto's `cast5` and `cast6` at every key length they take. Contract tests
cover error state, untouched output on errors and preserved output tails. A
test requires every engine API to document whether it is constant or variable
time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_cast --locked
cargo clippy -p tc_cast --all-targets --locked -- -D warnings
cargo fmt -p tc_cast --check
cargo doc -p tc_cast --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_cast --list --locked
cargo publish -p tc_cast --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
