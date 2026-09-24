# tc_aes

[![crates.io](https://img.shields.io/crates/v/tc_aes.svg)](https://crates.io/crates/tc_aes)
[![docs.rs](https://docs.rs/tc_aes/badge.svg)](https://docs.rs/tc_aes)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

AES-128, AES-192 and AES-256 block ciphers with AES-NI, RustCrypto,
table-based and small-footprint engines. Every engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, and a
dispatcher picks the safest engine available at runtime.

The crate is `no_std` and needs no allocator. It depends on `tc_block_cipher`
and [`tc_zeroize`](https://crates.io/crates/tc_zeroize) everywhere, on
[`tc_runtime`](https://crates.io/crates/tc_runtime) for AES-NI detection on
x86 and x86-64 only, and on RustCrypto's [`aes`](https://crates.io/crates/aes)
only with the default-off `rustcrypto` feature. The AES-NI engine confines its
`unsafe` intrinsics to one module behind a detection token.

Requires Rust 1.85 or later (edition 2024) for the default build. The optional
`rustcrypto` feature follows the minimum Rust version of the `aes` crate
instead: `aes` 0.9.3 requires Rust 1.89, and Cargo's MSRV-aware resolver can
select an earlier release that builds with an older toolchain.

## Types

- `AesEngine` — picks the safest engine at construction; constant time unless
  it falls back to the table engine.
- `AesX86Engine` — AES-NI on x86 and x86-64; constant time.
- `AesRustCryptoEngine` (`rustcrypto`) — RustCrypto's `aes`; constant time.
- `AesTableEngine` — portable T-tables; variable time.
- `AesLightEngine` — portable, smaller tables; variable time.

Every engine takes a 16-, 24- or 32-byte key through any `KeyParams`; another
length returns `InitError::InvalidKeyLength` and keeps the previous key.
`process_block` transforms the first 16 bytes and returns 16, returning
`BlockError::NotInitialised` before `init` and `BlockError::BufferTooShort` for
a buffer shorter than a block. `Display` writes `"AES"` without inspecting key
material. The constants `ALGO_NAME`, `BLOCK_BYTES` and `KEY_BYTES` hold
`"AES"`, `16` and `[16, 24, 32]`.

`AesEngine`, `AesTableEngine`, `AesLightEngine` and `AesRustCryptoEngine`
implement `Default`; the last three have `const fn new`. `AesX86Engine::new`
returns an `Option`, and `AesX86Engine::is_supported` reports whether it
returns an engine.

## Features

- `rustcrypto` (off by default) — adds `AesRustCryptoEngine`, which `AesEngine`
  then always uses; pulls in the `aes` crate and its minimum Rust version.

## Usage

```toml
[dependencies]
tc_aes = "0.1.0"
tc_block_cipher = "0.1.0"
```

For a constant-time engine on processors without AES-NI:

```toml
[dependencies]
tc_aes = { version = "0.1.0", features = ["rustcrypto"] }
tc_block_cipher = "0.1.0"
```

This example uses the AES-128 known-answer vector from FIPS 197:

```rust
use tc_aes::{AesEngine, BLOCK_BYTES};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};

let key: [u8; 16] = core::array::from_fn(|i| i as u8);
let plaintext: [u8; 16] = core::array::from_fn(|i| (i as u8) * 0x11);

let mut engine = AesEngine::new();
engine
    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
    .expect("AES accepts a 16-byte key");
let mut ciphertext = [0; BLOCK_BYTES];
assert_eq!(engine.process_block(&plaintext, &mut ciphertext), Ok(BLOCK_BYTES));
assert_eq!(ciphertext, [
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
]);
```

The crate and engine documentation carry executable examples for every engine.

## Security and engine selection

- `AesX86Engine` uses AES-NI with a constant-time key schedule and requires
  runtime support.
- `AesRustCryptoEngine` provides hardware acceleration with a constant-time
  software fallback on supported platforms.
- `AesTableEngine` and `AesLightEngine` use secret-dependent table lookups and
  are variable time. Light trades smaller lookup tables for lower speed here.
- `AesEngine` chooses RustCrypto when the `rustcrypto` feature is enabled.
  Otherwise it chooses AES-NI when available,
  falling back to Table. Its default configuration therefore does not guarantee
  constant-time processing on every host.

Engines keep an expanded key schedule rather than borrowing the caller's key,
and wipe it on drop. Wiping does not reach the caller's key buffer or copies
left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, nonce management, mode of operation or authentication. Do not
encrypt a message by independently encrypting each block; use an appropriate
authenticated-encryption construction.

## Benchmarks

Single-block timings for every engine, and the commands to reproduce them, are
in [BENCHES.md](BENCHES.md). In short, AES-NI and RustCrypto were several times
faster than the table and light engines on an x86-64 host with AES-NI.

## Validation

Every engine is tested against the FIPS 197 Appendix C vectors for all three
key sizes in both directions, and for processing before initialization, short
and long buffers, and rejected key lengths that keep the previous key. The
engines are cross-checked on pseudorandom keys and blocks: AES-NI against the
table and light engines, table against light, and with `rustcrypto` each of the
three against RustCrypto. The key
expansion is checked against FIPS 197 Appendix A, and the S-boxes, computed at
compile time from the field arithmetic, against their standard values. An
integration test checks each engine's `Display` output. AES-NI tests pass
without running where the processor lacks it.

Missing public documentation and unsafe operations outside an explicit `unsafe`
block are rejected by crate-level lints.

Run these commands from the workspace root:

```text
cargo test -p tc_aes --locked
cargo test -p tc_aes --locked --features rustcrypto
cargo test -p tc_aes --locked --features tc_runtime/disable-x86-aes-ni
cargo clippy -p tc_aes --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_aes --check
cargo doc -p tc_aes --no-deps --all-features --locked
```

The third command, on x86 and x86-64, disables AES-NI detection in
`tc_runtime` so the dispatcher's table fallback runs on a processor that has
AES-NI.

Before a release, check the archive contents and run publication validation
from a committed checkout. Until `tc_block_cipher` 0.1.0 is on crates.io, name
both crates in one invocation so `tc_aes` is verified against the local
`tc_block_cipher`:

```text
cargo package -p tc_block_cipher -p tc_aes --list --locked
cargo publish -p tc_block_cipher -p tc_aes --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the
benchmark results, the source, the integration test and the benchmark. It must
not include `target/` or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
