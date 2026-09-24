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

| Type | Availability | Timing |
| --- | --- | --- |
| `AesEngine` | Always | Dispatches once at construction: `AesRustCryptoEngine` with the `rustcrypto` feature, otherwise `AesX86Engine` where AES-NI is detected, otherwise `AesTableEngine`. Constant time unless it falls back to the table engine |
| `AesX86Engine` | x86 and x86-64; `new()` returns `None` without AES-NI | Constant time, including the key schedule |
| `AesRustCryptoEngine` | `rustcrypto` feature | Constant time on every backend the `aes` crate selects |
| `AesTableEngine` | Always | Variable time: key- and data-dependent T-table lookups. The key schedule is constant time |
| `AesLightEngine` | Always | Variable time: key- and data-dependent S-box lookups in both the key schedule and the rounds |

| Item | Contract |
| --- | --- |
| `BlockCipherInit::init` | Accepts any `KeyParams` holding 16, 24 or 32 bytes. Other lengths return `InitError::InvalidKeyLength` and keep the previous key and direction. Calling it again installs a new key or direction |
| `BlockCipher::block_size` | Always 16 |
| `BlockCipher::process_block` | Transforms the first 16 bytes of `input` into the first 16 of `output` and returns 16, leaving any output tail intact. Returns `BlockError::NotInitialised` before a key is installed and `BlockError::BufferTooShort` when either buffer is shorter than a block |
| `Display` | Writes `ALGO_NAME` (`"AES"`) for every engine, key size and direction, without inspecting key material |
| `ALGO_NAME`, `BLOCK_BYTES`, `KEY_BYTES` | `"AES"`, `16`, and `[16, 24, 32]` |

`AesEngine`, `AesTableEngine`, `AesLightEngine` and `AesRustCryptoEngine`
implement `Default`; the last three have `const fn new`. `AesX86Engine::new`
returns an `Option`, and `AesX86Engine::is_supported` reports whether it
returns an engine.

## Features

| Features | Support |
| --- | --- |
| None (default) | Core-only `no_std`: the dispatcher, the table and light engines, and `AesX86Engine` on x86 and x86-64 |
| `rustcrypto` | All default support plus `AesRustCryptoEngine`, which `AesEngine` then always uses; adds the `aes` crate with its `zeroize` feature, and with it that crate's minimum Rust version |

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

## Single-block benchmark results

Measured on 2026-09-23 on the local Windows x86-64 host with AES-NI available,
using Rust 1.98.0 and Cargo's optimized bench profile. The CPU model was not
recorded. These results describe this host and run, not a cross-platform ranking.

Each of the 24 cases used Criterion with a 3-second warm-up, a 15-second
measurement window and 100 samples. Values below are Criterion's central time
estimates, rounded to one decimal place.

**Nanoseconds per 16-byte block; lower is better. Each cell is encryption /
decryption.**

| Engine | AES-128 | AES-192 | AES-256 |
| --- | ---: | ---: | ---: |
| `AesX86Engine` (AES-NI) | 12.1 / 10.2 | 12.0 / 10.4 | 13.4 / 11.6 |
| `AesRustCryptoEngine` | 14.2 / 11.6 | 14.4 / 12.4 | 15.0 / 13.4 |
| `AesTableEngine` | 70.5 / 77.3 | 81.1 / 87.8 | 91.5 / 101.3 |
| `AesLightEngine` | 118.0 / 147.3 | 140.6 / 173.9 | 161.8 / 207.9 |

AES-NI was fastest in this run, followed by RustCrypto, Table and Light.
The measurements include each engine's `process_block` API overhead but exclude
key setup, construction and final drop. They call the four engines directly,
not the `AesEngine` dispatcher. Decryption uses ciphertext prepared before timing.

These are single-block measurements, not multi-block parallel throughput or
constant-time verification. Some samples were outliers; system load and CPU
behaviour can affect small differences. The RustCrypto engine chooses its own
backend; this benchmark does not report that internal selection.

### Running the benchmarks

Reproduce the four-engine single-block comparison:

```powershell
cargo bench -p tc_aes --bench aes --all-features --locked -- '^aes/(encrypt|decrypt)/(table|light|aes-ni|rustcrypto)/'
```

Run all benchmarks, including dispatcher and key setup measurements:

```powershell
cargo bench -p tc_aes --bench aes --all-features --locked
```

Setup benchmarks reinitialise an existing engine, including replacement of its
previous key schedule. They exclude construction and final drop. AES-NI cases
are skipped when unavailable; RustCrypto cases require the `rustcrypto` feature.
The full suite takes roughly 18 minutes on a host running all 60 cases, plus
compilation and analysis time.

For a smoke test without performance measurement:

```powershell
cargo bench -p tc_aes --bench aes --all-features --locked -- --test
```

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
source, the integration test and the benchmark. It must not include `target/`
or other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
