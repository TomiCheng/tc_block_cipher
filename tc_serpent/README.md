# tc_serpent

[![crates.io](https://img.shields.io/crates/v/tc_serpent.svg)](https://crates.io/crates/tc_serpent)
[![docs.rs](https://docs.rs/tc_serpent/badge.svg)](https://docs.rs/tc_serpent)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The Serpent block cipher, an AES finalist, and Tnepres, its byte-swapped
variant, with a key of 4 to 32 bytes in four-byte steps and a 128-bit block. The
engines implement the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits.

The crate is `no_std`, needs no allocator and contains no `unsafe` code. It
depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `SerpentEngine` — Serpent in its conventional little-endian representation; constant time.
- `TnepresEngine` — Tnepres, which reverses the bytes and words of the key and block; constant time.

Tnepres came out of an endianness issue in the test vectors of the AES
submission. It is a different cipher on the wire, not an alias for Serpent, and
is here for the data that uses it.

Every engine takes its key through any `KeyParams`, such as `KeyRef`. Another
key length returns `InitError::InvalidKeyLength` and keeps the previous key and
direction. `process_block` transforms the first block and returns its length,
returning `BlockError::NotInitialised` before `init` and
`BlockError::BufferTooShort` for a buffer shorter than a block, without touching
the output. `Display` writes `"Serpent"` or `"Tnepres"` without inspecting key
material.

The constants `BLOCK_BYTES`, `MIN_KEY_BYTES`, `MAX_KEY_BYTES` and
`KEY_STEP_BYTES` hold the block length, `16`, the shortest and longest keys, `4`
and `32`, and the step between accepted key lengths, `4`. `SERPENT_ALGO_NAME` and
`TNEPRES_ALGO_NAME` hold the names. Every engine implements `Default` and has
`const fn new`.

## Usage

```toml
[dependencies]
tc_serpent = "0.1.0"
tc_block_cipher = "0.1.0"
```

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_serpent::SerpentEngine;

let key = [0x42; 32];
let mut engine = SerpentEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("Serpent accepts a 32-byte key");
let mut ciphertext = [0; 16];
assert_eq!(engine.process_block(&[0x11; 16], &mut ciphertext), Ok(16));
```

The crate and engine documentation carry executable examples.

## Security

Both engines are constant time with respect to key and block contents: the
S-boxes are bitsliced, with Boolean operations and fixed rotations and without
secret-dependent branches or table indices. Key length, representation and
direction are public.

Each engine keeps its expanded working key rather than borrowing the caller's
key, and wipes it when it is replaced and on drop. Wiping does not reach the
caller's key buffer or copies left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Validation

The engines are tested against the vectors of Bouncy Castle's `SerpentTest` and
`TnepresTest`, in both directions and through their hundred-iteration vectors.
Serpent is also tested against RustCrypto's `serpent` on the known vector and 64
key and block pairs at each key length from 16 bytes, since that crate rejects
shorter keys. Contract tests cover error state, untouched output on errors and
preserved output tails for each engine. A test requires every engine API to
document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_serpent --locked
cargo clippy -p tc_serpent --all-targets --locked -- -D warnings
cargo fmt -p tc_serpent --check
cargo doc -p tc_serpent --no-deps --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_serpent --list --locked
cargo publish -p tc_serpent --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
