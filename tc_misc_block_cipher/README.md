# tc_misc_block_cipher

[![crates.io](https://img.shields.io/crates/v/tc_misc_block_cipher.svg)](https://crates.io/crates/tc_misc_block_cipher)
[![docs.rs](https://docs.rs/tc_misc_block_cipher/badge.svg)](https://docs.rs/tc_misc_block_cipher)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Less common block ciphers, ported from Bouncy Castle, one Cargo feature each and
none on by default: IDEA, Noekeon, Rijndael, SKIPJACK, TEA and XTEA. Every engine
implements the [`tc_block_cipher`](https://crates.io/crates/tc_block_cipher)
traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Features and types

Each feature adds a module of the same name.

- `idea`: `idea::IdeaEngine`, IDEA with a 16-byte key and an 8-byte block; variable time.
- `noekeon`: `noekeon::NoekeonEngine`, Noekeon in direct-key mode with a 16-byte key and block; constant time.
- `rijndael`: `rijndael::RijndaelEngine<BLOCK_COLUMNS>` and its aliases `Rijndael128Engine` to `Rijndael256Engine`, Rijndael with a 16-, 20-, 24-, 28- or 32-byte block and key in any combination; variable time.
- `skipjack`: `skipjack::SkipjackEngine`, SKIPJACK with a 10-byte key and an 8-byte block; variable time.
- `tea`: `tea::TeaEngine` and `tea::XteaEngine`, TEA and XTEA with a 16-byte key and an 8-byte block; constant time. The two are not compatible.

Every engine takes its key through any `KeyParams`, such as `KeyRef`. Another
key length returns `InitError::InvalidKeyLength` and keeps the previous key and
direction. `process_block` transforms the first block and returns its length,
returning `BlockError::NotInitialised` before `init` and
`BlockError::BufferTooShort` for a buffer shorter than a block, without touching
the output. `Display` writes the algorithm name without inspecting key material.

Each module holds the constants for its name, block length and key lengths, such
as `ALGO_NAME`, `BLOCK_BYTES` and `KEY_BYTES`. Every engine implements `Default`
and has `const fn new`. `RijndaelEngine` rejects a block width outside `4..=8`
columns at compile time.

## Usage

```toml
[dependencies]
tc_misc_block_cipher = { version = "0.1.0", features = ["tea"] }
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_misc_block_cipher::tea::XteaEngine;

let key = [0x42; 16];
let mut engine = XteaEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("XTEA accepts a 16-byte key");
let mut ciphertext = [0; 8];
assert_eq!(engine.process_block(&[0x11; 8], &mut ciphertext), Ok(8));
```

The crate and engine documentation carry executable examples.

## Security

Noekeon, TEA and XTEA are constant time with respect to key and block contents:
they use only additions, bitwise operations and fixed shifts or rotations.

IDEA, Rijndael and SKIPJACK are variable time, so timing can leak the key. IDEA's
multiplication branches on secret values and its decryption key setup runs a
key-dependent Euclidean loop. Rijndael and SKIPJACK look up tables with secret
data, and Rijndael's field multiplication branches on it. Use them only where
timing leakage is outside the threat model; this crate provides no constant-time
alternative. For AES, use a dedicated AES crate rather than Rijndael with a
128-bit block.

These ciphers are here for the formats and systems that still use them. The
64-bit block of IDEA, SKIPJACK, TEA and XTEA makes them unfit for large amounts
of data under one key, SKIPJACK's 80-bit key is too short for new designs, and
every TEA key has equivalent keys.

Each engine keeps its expanded schedule rather than borrowing the caller's key,
and wipes it when it is replaced and on drop. Wiping does not reach the caller's
key buffer or copies left in registers and on the stack.

These are block-cipher primitives, not a message-encryption format. They supply
no padding, mode of operation or authentication.

## Validation

Each feature has its own test files:

- IDEA: the vectors of Bouncy Castle's `IDEATest` and the reference vector, and
  RustCrypto's `idea` on the known vector and 64 key and block pairs.
- Noekeon: the vectors of Bouncy Castle's `NoekeonTest`.
- Rijndael: the vectors of Bouncy Castle's `RijndaelTest` at every block size,
  with its ten-thousand-iteration vectors, and RustCrypto's `aes` on the known
  vector and 64 key and block pairs at each AES key size.
- SKIPJACK: the vector of Bouncy Castle's `SkipjackTest`.
- TEA and XTEA: the vectors of Bouncy Castle's `TEATest` and `XTEATest`, and
  RustCrypto's `xtea` on a known answer and 64 key and block pairs.

Vectors run in both directions. Contract tests cover error state, untouched
output on errors and preserved output tails for each engine. A test for each
feature requires every engine API to document whether it is constant or variable
time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_misc_block_cipher --locked --all-features
cargo clippy -p tc_misc_block_cipher --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_misc_block_cipher --check
cargo doc -p tc_misc_block_cipher --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_misc_block_cipher --list --locked
cargo publish -p tc_misc_block_cipher --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
