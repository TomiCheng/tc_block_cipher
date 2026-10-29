# tc_sm4

[![crates.io](https://img.shields.io/crates/v/tc_sm4.svg)](https://crates.io/crates/tc_sm4)
[![docs.rs](https://docs.rs/tc_sm4/badge.svg)](https://docs.rs/tc_sm4)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The SM4 block cipher, the Chinese national standard GB/T 32907-2016, with a
128-bit key and a 128-bit block. The engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `Sm4Engine` — SM4 with a 16-byte key and a 16-byte block; variable time.

The engine takes its key through any `KeyParams`, such as `KeyRef`. Another
key length returns `InitError::InvalidKeyLength` and keeps the previous key.
`process_block` transforms the first block and returns its length, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort`
for a buffer shorter than a block, without touching the output. `Display`
writes `"SM4"` without inspecting key material.

The constants `BLOCK_BYTES` and `KEY_BYTES`, both 16, give the block and key
lengths, and `ALGO_NAME` holds the name. The engine implements `Default` and
has `const fn new`.

## Usage

```toml
[dependencies]
tc_sm4 = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_sm4::Sm4Engine;

let key = [0x42; 16];
let mut engine = Sm4Engine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("SM4 accepts a 16-byte key");
let mut ciphertext = [0; 16];
assert_eq!(engine.process_block(&[0x11; 16], &mut ciphertext), Ok(16));
```

The crate and engine documentation carry executable examples.

## Security

The engine is variable time: key setup and block processing look up the S-box
with secret data, so cache timing can leak the key. Use it only where
cache-timing leakage is outside the threat model; this crate provides no
constant-time engine.

The engine keeps an expanded key schedule rather than borrowing the caller's
key, and wipes it when it is replaced and on drop. Wiping does not reach the
caller's key buffer or copies left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Validation

The engine is tested against the Bouncy Castle vectors, the published single
block and the million-iteration chain, in both directions, and against
RustCrypto's `sm4` on random keys and blocks. Contract tests cover error
state, untouched output on errors and preserved output tails. A test requires
every engine API to document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_sm4 --locked
cargo clippy -p tc_sm4 --all-targets --locked -- -D warnings
cargo fmt -p tc_sm4 --check
cargo doc -p tc_sm4 --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_sm4 --list --locked
cargo publish -p tc_sm4 --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
