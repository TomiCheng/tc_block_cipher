# tc_dstu7624

[![crates.io](https://img.shields.io/crates/v/tc_dstu7624.svg)](https://crates.io/crates/tc_dstu7624)
[![docs.rs](https://docs.rs/tc_dstu7624/badge.svg)](https://docs.rs/tc_dstu7624)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The DSTU 7624:2014 (Kalyna) block cipher, the Ukrainian national standard, with
128-, 256- and 512-bit blocks. Every engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `Dstu7624Engine128` — 128-bit block with a 128- or 256-bit key; variable
  time.
- `Dstu7624Engine256` — 256-bit block with a 256- or 512-bit key; variable
  time.
- `Dstu7624Engine512` — 512-bit block with a 512-bit key; variable time.
- `Dstu7624Engine` — the engine behind the three aliases, whose const
  parameter counts 64-bit block words; only 2, 4 and 8 are implemented.

Each engine takes its key through any `KeyParams`, such as `KeyRef`. Another
key length returns `InitError::InvalidKeyLength` and keeps the previous key.
`process_block` transforms the first block and returns its length, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort`
for a buffer shorter than a block, without touching the output. `Display`
writes `"DSTU7624"` without inspecting key material.

The constants `BLOCK_BITS` and `KEY_BYTES` list the supported block lengths,
`[128, 256, 512]`, and key lengths, `[16, 32, 64]`, and `ALGO_NAME` holds the
name. Every engine implements `Default` and has `const fn new`.

## Usage

```toml
[dependencies]
tc_dstu7624 = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_dstu7624::Dstu7624Engine128;

let key = [0x42; 16];
let mut engine = Dstu7624Engine128::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("Kalyna-128 accepts a 16-byte key");
let mut ciphertext = [0; 16];
assert_eq!(engine.process_block(&[0x11; 16], &mut ciphertext), Ok(16));
```

The crate and engine documentation carry executable examples.

## Security

Every engine is variable time: key setup and block processing look up S-boxes
with secret data, so cache timing can leak the key. Use it only where
cache-timing leakage is outside the threat model; this crate provides no
constant-time engine.

Engines keep an expanded key schedule rather than borrowing the caller's key,
and wipe it when it is replaced and on drop. Wiping does not reach the caller's
key buffer or copies left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Validation

The engines are tested against the Bouncy Castle ECB vectors for every block
and key size, in both directions. Contract tests cover error state, untouched
output on errors and preserved output tails for every block and key size. A
test requires every engine API to document whether it is constant or variable
time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_dstu7624 --locked
cargo clippy -p tc_dstu7624 --all-targets --locked -- -D warnings
cargo fmt -p tc_dstu7624 --check
cargo doc -p tc_dstu7624 --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_dstu7624 --list --locked
cargo publish -p tc_dstu7624 --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
