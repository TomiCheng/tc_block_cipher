# tc_camellia

[![crates.io](https://img.shields.io/crates/v/tc_camellia.svg)](https://crates.io/crates/tc_camellia)
[![docs.rs](https://docs.rs/tc_camellia/badge.svg)](https://docs.rs/tc_camellia)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Camellia-128, Camellia-192 and Camellia-256 block ciphers, as specified by
RFC 3713, with T-table, small-footprint and RustCrypto engines. Every engine
implements the [`tc_block_cipher`](https://crates.io/crates/tc_block_cipher)
traits, and `CamelliaEngine` picks an engine at compile time.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and [`tc_zeroize`](https://crates.io/crates/tc_zeroize),
and on RustCrypto's [`camellia`](https://crates.io/crates/camellia) only with
the default-off `rustcrypto` feature.

Requires Rust 1.85 or later (edition 2024) for the default build. The optional
`rustcrypto` feature follows the minimum Rust version of the `camellia` crate
instead, which is 1.85 for `camellia` 0.2.1.

## Types

- `CamelliaEngine` — Camellia on the RustCrypto engine with `rustcrypto`,
  otherwise on the table engine; variable time.
- `CamelliaTableEngine` — four 256-entry `u32` T-tables; variable time.
- `CamelliaLightEngine` — a single 256-byte S-box, for small code and data;
  variable time.
- `CamelliaRustCryptoEngine` (`rustcrypto`) — RustCrypto's `camellia`;
  variable time.

Every engine takes a 16-, 24- or 32-byte key. Another length returns
`InitError::InvalidKeyLength` and keeps the previous key and direction.
`process_block` transforms the first 16 bytes and returns 16, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort`
for a buffer shorter than a block, without touching the output. `Display`
writes `"Camellia"` without inspecting key material.

The constants `ALGO_NAME`, `BLOCK_BYTES` and `KEY_BYTES` hold the name, the
block length, `16`, and the accepted key lengths, `[16, 24, 32]`. Every engine
implements `Default` and has `const fn new`.

## Features

- `rustcrypto` (off by default) — adds `CamelliaRustCryptoEngine`, which
  `CamelliaEngine` then uses; pulls in the `camellia` crate, with its `zeroize`
  feature, and its minimum Rust version.

## Usage

```toml
[dependencies]
tc_block_cipher = "0.1.0"
tc_camellia = "0.1.0"
```

This example uses the 128-bit vector from RFC 3713:

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_camellia::{BLOCK_BYTES, CamelliaEngine};

let key = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

let mut engine = CamelliaEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("Camellia accepts a 16-byte key");
let mut ciphertext = [0; BLOCK_BYTES];
assert_eq!(engine.process_block(&key, &mut ciphertext), Ok(BLOCK_BYTES));
assert_eq!(ciphertext, [
    0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
    0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43,
]);
```

RFC 3713 encrypts the key itself in its examples, so the key doubles as the
plaintext here. The crate and engine documentation carry executable examples
for every engine.

## Security

Every engine is variable time. Key expansion and block processing both look up
S-boxes with secret data, so cache timing can leak the key. The light engine's
single 256-byte table spans fewer cache lines than the table engine's 4 KiB,
but it is still indexed by secret data, and `CamelliaEngine` does not select
it; use `CamelliaLightEngine` directly to narrow the footprint. RustCrypto's
`camellia` also uses
S-box tables, so the `rustcrypto` feature changes the implementation, not the
timing contract. This crate provides no constant-time engine; use it only
where cache-timing leakage is outside the threat model.

Engines keep an expanded key schedule rather than borrowing the caller's key,
and wipe it on drop. Wiping does not reach the caller's key buffer or copies
left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Benchmarks

Key setup and single-block timings for the table, light and RustCrypto
engines, and the commands to reproduce them, are in [BENCHES.md](BENCHES.md).

## Validation

The engines are tested against the RFC 3713 vectors for all three key sizes,
in both directions. Contract tests cover key and buffer errors, state kept on
errors, untouched output, processing only the first block of a longer buffer
and `Display` for every engine. Every engine is cross-checked against
RustCrypto's `camellia` on the RFC 3713 vectors and on pseudorandom keys and
blocks in both directions. A test requires every engine API to document
whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_camellia --locked
cargo test -p tc_camellia --locked --features rustcrypto
cargo clippy -p tc_camellia --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_camellia --check
cargo doc -p tc_camellia --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_camellia --list --locked
cargo publish -p tc_camellia --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
benchmark results, the source, the integration tests and the benchmark. It must
not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
