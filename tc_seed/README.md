# tc_seed

[![crates.io](https://img.shields.io/crates/v/tc_seed.svg)](https://crates.io/crates/tc_seed)
[![docs.rs](https://docs.rs/tc_seed/badge.svg)](https://docs.rs/tc_seed)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The SEED block cipher, the Korean standard of KISA in RFC 4269, with a 128-bit key
and a 128-bit block. The engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `SeedEngine` — SEED with a 16-byte key and a 16-byte block; variable time.

The engine takes its key through any `KeyParams`, such as `KeyRef`. Another
key length returns `InitError::InvalidKeyLength` and keeps the previous key.
`process_block` transforms the first block and returns its length, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort`
for a buffer shorter than a block, without touching the output. `Display`
writes `"SEED"` without inspecting key material.

The constants `BLOCK_BYTES` and `KEY_BYTES`, both 16, give the block and key
lengths, and `ALGO_NAME` holds the name. The engine implements `Default` and
has `const fn new`.

## Usage

```toml
[dependencies]
tc_seed = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_seed::SeedEngine;

let key = [0x42; 16];
let mut engine = SeedEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("SEED accepts a 16-byte key");
let mut ciphertext = [0; 16];
assert_eq!(engine.process_block(&[0x11; 16], &mut ciphertext), Ok(16));
```

The crate and engine documentation carry executable examples.

## Security

The engine is variable time: key setup and block processing look up the SS0 to
SS3 S-boxes with secret data, so cache timing can leak the key. Use it only
where cache-timing leakage is outside the threat model; this crate provides no
constant-time engine.

The engine keeps an expanded working key rather than borrowing the caller's
key, and wipes it when it is replaced and on drop. Wiping does not reach the
caller's key buffer or copies left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Validation

The engine is tested against the RFC 4009 vectors that Bouncy Castle's
`SEEDTest` uses, in both directions. Contract tests cover error state,
untouched output on errors and preserved output tails. A test requires every
engine API to document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_seed --locked
cargo clippy -p tc_seed --all-targets --locked -- -D warnings
cargo fmt -p tc_seed --check
cargo doc -p tc_seed --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_seed --list --locked
cargo publish -p tc_seed --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
