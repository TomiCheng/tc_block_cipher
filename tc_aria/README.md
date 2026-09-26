# tc_aria

[![crates.io](https://img.shields.io/crates/v/tc_aria.svg)](https://crates.io/crates/tc_aria)
[![docs.rs](https://docs.rs/tc_aria/badge.svg)](https://docs.rs/tc_aria)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

ARIA-128, ARIA-192 and ARIA-256 block ciphers, as specified by RFC 5794, with
table-based and RustCrypto engines. Every engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, and
`AriaEngine` picks an engine at compile time.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and [`tc_zeroize`](https://crates.io/crates/tc_zeroize),
and on RustCrypto's [`aria`](https://crates.io/crates/aria) only with the
default-off `rustcrypto` feature.

Requires Rust 1.85 or later (edition 2024) for the default build. The optional
`rustcrypto` feature follows the minimum Rust version of the `aria` crate
instead, which is 1.85 for `aria` 0.2.0.

## Types

- `AriaEngine` — ARIA on the RustCrypto engine with `rustcrypto`, otherwise on
  the table engine; variable time.
- `AriaTableEngine` — portable S-box tables; variable time.
- `AriaRustCryptoEngine` (`rustcrypto`) — RustCrypto's `aria`; variable time.

Every engine takes a 16-, 24- or 32-byte key. Another length returns
`InitError::InvalidKeyLength` and keeps the previous key and direction.
`process_block` transforms the first 16 bytes and returns 16, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort`
for a buffer shorter than a block, without touching the output. `Display`
writes `"ARIA"` without inspecting key material.

The constants `ALGO_NAME`, `BLOCK_BYTES` and `KEY_BYTES` hold the name, the
block length, `16`, and the accepted key lengths, `[16, 24, 32]`. Every engine
implements `Default` and has `const fn new`.

## Features

- `rustcrypto` (off by default) — adds `AriaRustCryptoEngine`, which
  `AriaEngine` then uses; pulls in the `aria` crate, with its `zeroize`
  feature, and its minimum Rust version.

## Usage

```toml
[dependencies]
tc_aria = "0.1.0"
tc_block_cipher = "0.1.0"
```

This example uses the 128-bit vector from RFC 5794:

```rust
use tc_aria::{AriaEngine, BLOCK_BYTES};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};

let key: [u8; 16] = core::array::from_fn(|i| i as u8);
let plaintext: [u8; 16] = core::array::from_fn(|i| (i as u8) * 0x11);

let mut engine = AriaEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("ARIA accepts a 16-byte key");
let mut ciphertext = [0; BLOCK_BYTES];
assert_eq!(engine.process_block(&plaintext, &mut ciphertext), Ok(BLOCK_BYTES));
assert_eq!(ciphertext, [
    0xd7, 0x18, 0xfb, 0xd6, 0xab, 0x64, 0x4c, 0x73,
    0x9d, 0xa9, 0x5f, 0x3b, 0xe6, 0x45, 0x17, 0x78,
]);
```

The crate and engine documentation carry executable examples for every engine.

## Security

Every engine is variable time. Key expansion and block processing both look up
S-boxes with secret data, so cache timing can leak the key. RustCrypto's `aria`
does not carry the constant-time guarantee of its AES implementation, so the
`rustcrypto` feature changes the implementation, not the timing contract. This
crate provides no constant-time engine; use it only where cache-timing leakage
is outside the threat model.

Engines keep an expanded key schedule rather than borrowing the caller's key,
and wipe it on drop. Wiping does not reach the caller's key buffer or copies
left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Benchmarks

Key setup and single-block timings for the table and RustCrypto engines, and
the commands to reproduce them, are in [BENCHES.md](BENCHES.md).

## Validation

The engines are tested against the RFC 5794 vectors for all three key sizes,
in both directions. Contract tests cover key and buffer errors, state kept on
errors, untouched output, processing only the first block of a longer buffer,
use through a trait object and `Display`. With `rustcrypto`, the table and
RustCrypto engines are cross-checked on pseudorandom keys and blocks in both
directions. A test requires every engine API to document whether it is
constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_aria --locked
cargo test -p tc_aria --locked --features rustcrypto
cargo clippy -p tc_aria --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_aria --check
cargo doc -p tc_aria --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_aria --list --locked
cargo publish -p tc_aria --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
benchmark results, the source, the integration tests and the benchmark. It must
not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
