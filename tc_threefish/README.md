# tc_threefish

[![crates.io](https://img.shields.io/crates/v/tc_threefish.svg)](https://crates.io/crates/tc_threefish)
[![docs.rs](https://docs.rs/tc_threefish/badge.svg)](https://docs.rs/tc_threefish)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The Threefish tweakable block ciphers with 256-, 512- and 1024-bit blocks, the
core of the Skein hash. Every engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Traits

- `ThreefishParams` — a `KeyParams` that also supplies an optional 16-byte
  tweak; implement it to pass a key and tweak from your own type.

## Types

- `Threefish256Engine` — 256-bit block with a 32-byte key; constant time.
- `Threefish512Engine` — 512-bit block with a 64-byte key; constant time.
- `Threefish1024Engine` — 1024-bit block with a 128-byte key; constant time.
- `ThreefishEngine` — the engine behind the three aliases, whose const
  parameter counts 64-bit block words; only 4, 8 and 16 compile.
- `ThreefishParamsRef` — a borrowed key with an optional borrowed tweak.

Each engine takes its key and tweak through any `ThreefishParams`. The key must
be one block long and the tweak, when present, 16 bytes; an absent tweak is all
zero. Another length returns `InitError::InvalidKeyLength` or
`InitError::InvalidTweakLength` and keeps the previous key, tweak and direction.
`process_block` transforms the first block and returns its length, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort`
for a buffer shorter than a block, without touching the output. `Display`
writes the variant name without inspecting key material.

The constant `TWEAK_BYTES` is 16, and `THREEFISH_256_ALGO_NAME`,
`THREEFISH_512_ALGO_NAME` and `THREEFISH_1024_ALGO_NAME` hold the names. Every
engine implements `Default` and has `const fn new`.

## Usage

```toml
[dependencies]
tc_threefish = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_threefish::{Threefish256Engine, ThreefishParamsRef};

let key = [0x42; 32];
let tweak = [0x11; 16];
let mut engine = Threefish256Engine::new();
engine
    .init(CipherDirection::Encrypt, &ThreefishParamsRef::with_tweak(&key, &tweak))
    .expect("Threefish-256 accepts a 32-byte key and a 16-byte tweak");
let mut ciphertext = [0; 32];
assert_eq!(engine.process_block(&[0x22; 32], &mut ciphertext), Ok(32));
```

The crate and engine documentation carry executable examples.

## Security

Every engine is constant time with respect to the key, the tweak and the block
contents: it uses only additions, XORs and rotations, and its schedule indices
follow the public round number.

Engines keep the expanded key and tweak rather than borrowing the caller's,
and wipe them when they are replaced and on drop. Wiping does not reach the
caller's buffers or copies left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Validation

The engines are tested against the vectors of the Skein 1.3 submission and the
Bouncy Castle tests for every block size, with zero and nonzero tweaks, in both
directions, and against RustCrypto's `threefish` with a nonzero tweak for every
block size. Contract tests cover error
state, untouched output on errors, preserved output tails, absent tweaks and
third-party parameter types. A test requires every engine API to document
whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_threefish --locked
cargo clippy -p tc_threefish --all-targets --locked -- -D warnings
cargo fmt -p tc_threefish --check
cargo doc -p tc_threefish --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_threefish --list --locked
cargo publish -p tc_threefish --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
