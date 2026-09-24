# tc_block_cipher

[![crates.io](https://img.shields.io/crates/v/tc_block_cipher.svg)](https://crates.io/crates/tc_block_cipher)
[![docs.rs](https://docs.rs/tc_block_cipher/badge.svg)](https://docs.rs/tc_block_cipher)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Shared traits, error types and key containers for single-block ciphers. Engine
crates such as [`tc_aes`](https://crates.io/crates/tc_aes) implement the
traits, and generic code that needs one block transformed at a time names only
the capabilities it uses. The crate implements no algorithm, mode of operation,
padding or authentication.

It is `no_std`, contains no `unsafe` code, and depends only on
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), which wipes the owned key
containers. A single, default-off `alloc` feature adds a heap-backed key
container through the sysroot `alloc` crate.

Requires Rust 1.85 or later (edition 2024).

## Traits

- `BlockCipherInit<P>` — `init` installs a key, or engine-specific parameters,
  for one direction.
- `BlockCipher` — `block_size` and `process_block` transform one block.
- `KeyParams` — `key` borrows the key bytes.

Initialization and processing are separate traits so generic callers can state
exactly which capabilities they need. Accepted key lengths, the handling of
buffers longer than a block, the state left by a rejected initialization, and
every timing guarantee belong to the engine, not to these traits.

## Types

- `CipherDirection` — `Encrypt` or `Decrypt`.
- `InitError`, `BlockError` — reusable initialization and processing errors.
- `KeyRef` — borrows a key slice.
- `KeyFixed<N>` — owns a key array and wipes it on drop.
- `KeyOwned` (`alloc`) — owns a key vector and wipes it on drop.

Both error enums are `#[non_exhaustive]` and implement `Clone`, `Copy`, `Debug`,
`PartialEq`, `Eq`, `Display` and `core::error::Error`. Engines may use them as
their associated error types or expose more specific failures of their own.

Every key container implements `KeyParams`. `KeyFixed` and `KeyOwned` also
implement `tc_zeroize::Zeroize` and `tc_zeroize::ZeroizeOnDrop`. No container
validates algorithm-specific key lengths; the receiving engine does.

## Features

- `alloc` (off by default) — adds `KeyOwned`; still `no_std`.

## Usage

Add the crate next to an engine crate:

```toml
[dependencies]
tc_block_cipher = "0.1.0"
tc_aes = "0.1.0"
```

`KeyOwned` needs the default-off `alloc` feature:

```toml
[dependencies]
tc_block_cipher = { version = "0.1.0", features = ["alloc"] }
```

Import the traits to reach an engine's methods, pick a key container, and
size buffers from `block_size`:

```rust
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyFixed};

let mut engine = AesEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyFixed::new([0x42; 16]))
    .expect("AES accepts a 16-byte key");
let mut output = [0; 16];
assert_eq!(engine.block_size(), output.len());
assert_eq!(engine.process_block(&[0; 16], &mut output), Ok(16));
```

The crate documentation has an executable example of implementing both traits
for an engine.

## Key handling and limitations

`KeyRef` leaves the caller's bytes untouched; the caller owns and wipes them.
`KeyFixed` and `KeyOwned` wipe only their own storage. Wiping does not reach the
caller's original array, copies made before a vector was moved in, engine key
schedules, or temporaries left in registers and on the stack. Drop-based wiping
requires the destructor to run.

The traits make no constant-time promise. Whether key setup and block
processing are constant time is documented by each engine. A block cipher alone
is not a message-encryption scheme: use it inside a mode of operation and an
authenticated-encryption construction.

## Validation

The crate documentation carries an executable example that implements both
traits and drives them through `KeyFixed` and `KeyRef`. Missing public
documentation is rejected by a crate-level lint, and `unsafe` code is forbidden.
The AES engines in `tc_aes` exercise the traits and error types against the FIPS
197 known-answer vectors.

Run these commands from the workspace root:

```text
cargo test -p tc_block_cipher --locked
cargo test -p tc_block_cipher --locked --features alloc
cargo clippy -p tc_block_cipher --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_block_cipher --check
cargo doc -p tc_block_cipher --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_block_cipher --list --locked
cargo publish -p tc_block_cipher --dry-run --locked
```

The archive includes both license texts, this README, the changelog and the
source. It must not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
