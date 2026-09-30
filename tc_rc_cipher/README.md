# tc_rc_cipher

[![crates.io](https://img.shields.io/crates/v/tc_rc_cipher.svg)](https://crates.io/crates/tc_rc_cipher)
[![docs.rs](https://docs.rs/tc_rc_cipher/badge.svg)](https://docs.rs/tc_rc_cipher)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

RC2, RC5 and RC6 block ciphers for interoperability with existing formats.
Every engine implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits. Do not
use these ciphers in new designs. RC4 is a stream cipher and is not part of
this crate.

The crate is `no_std`, needs no allocator by default and contains no `unsafe`
code. It depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize), and on RustCrypto's
[`rc2`](https://crates.io/crates/rc2) only with the default-off `rustcrypto`
feature.

Requires Rust 1.85 or later (edition 2024) for the default build and the
`alloc` feature. The optional `rustcrypto` feature follows the minimum Rust
version of the `rc2` crate instead, which is 1.85 for `rc2` 0.9.0.

## Types

- `Rc2Engine` — RC2 on the RustCrypto engine with `rustcrypto`, otherwise on
  the table engine; variable time.
- `Rc2TableEngine` — portable RC2; variable time.
- `Rc2RustCryptoEngine` (`rustcrypto`) — RustCrypto's `rc2`; variable time.
- `Rc532Engine`, `Rc564Engine` — RC5 with 32- and 64-bit words; constant time
  on processors with operand-independent rotations.
- `Rc6Engine` — RC6-32/20; constant time on processors with fixed-latency
  rotations and 32-bit multiplication.
- `Rc2ParamsRef`, `Rc5ParamsRef` — borrowed key with its RC2 effective size or
  RC5 round count.
- `Rc2ParamsOwned`, `Rc5ParamsOwned` (`alloc`) — the same, owning the key and
  wiping it on drop.

RC2 takes a 1- to 128-byte key and an effective key size of 1 to 1024 bits,
and processes 8-byte blocks. RC5 takes a 1- to 255-byte key and 0 to 255
rounds; RC5-32 processes 8-byte blocks and RC5-64 16-byte blocks. RC6 takes a
1- to 255-byte key through any `KeyParams`, such as `KeyRef`, and processes
16-byte blocks. An invalid key length, effective size or round count returns
`InitError::InvalidKeyLength`, `InvalidEffectiveKeyBits` or `InvalidRounds`
and keeps the previous key. `process_block` transforms the first block,
returning `BlockError::NotInitialised` before `init` and
`BlockError::BufferTooShort` for a buffer shorter than a block, without
touching the output. `Display` writes `"RC2"`, `"RC5-32"`, `"RC5-64"` or
`"RC6"`.

Constants named after their algorithm hold the block and key limits, such as
`RC2_BLOCK_BYTES`, `RC2_MAX_EFFECTIVE_KEY_BITS`, `RC5_DEFAULT_ROUNDS` and
`RC6_MAX_KEY_BYTES`. Every engine implements `Default` and has `const fn new`.

## Traits

- `Rc2Params` — supplies an RC2 key and its effective size in bits.
- `Rc5Params` — supplies an RC5 key and its round count.

## Features

- `alloc` (off by default) — adds `Rc2ParamsOwned` and `Rc5ParamsOwned`.
- `rustcrypto` (off by default) — adds `Rc2RustCryptoEngine`, which
  `Rc2Engine` then uses; pulls in the `rc2` crate and its minimum Rust version.

## Usage

```toml
[dependencies]
tc_rc_cipher = "0.1.0"
tc_block_cipher = "0.1.0"
```

This example uses the RFC 2268 test vector:

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_rc_cipher::{Rc2Engine, Rc2ParamsRef};

let mut engine = Rc2Engine::new();
engine
    .init(
        CipherDirection::Encrypt,
        &Rc2ParamsRef::with_effective_key_bits(&[0; 8], 63),
    )
    .expect("RC2 accepts an 8-byte key with 63 effective bits");
let mut ciphertext = [0; 8];
assert_eq!(engine.process_block(&[0; 8], &mut ciphertext), Ok(8));
assert_eq!(ciphertext, [0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff]);
```

The crate and engine documentation carry executable examples for every engine.

## Security

Every RC2 engine is variable time: key setup indexes the PI table with key
bytes, and every block indexes the expanded key with block data, so cache
timing can leak the key. Use RC2 only where cache-timing leakage is outside the
threat model; this crate provides no constant-time RC2 engine.

RC5 and RC6 are constant time only under hardware assumptions: their
data-dependent rotations, and RC6's 32-bit multiplications, must take a fixed
time, as on mainstream x86, x86-64 and AArch64. Processors without a barrel
shifter or with early-terminating multipliers can leak secret data.

Engines keep an expanded key schedule rather than borrowing the caller's key,
and wipe it when it is replaced and on drop. Wiping does not reach the caller's
key buffer or copies left in registers and on the stack.

This is a block-cipher primitive, not a message-encryption format. It supplies
no padding, mode of operation or authentication.

## Validation

The engines are tested against RFC 2268 and Bouncy Castle vectors for RC2,
RFC 2040 and Bouncy Castle vectors for RC5, and the AES submission and Bouncy
Castle vectors for RC6, in both directions. Contract tests cover error state,
untouched output on errors, preserved output tails and dynamic dispatch for
every engine, and every RC2 effective size from 1 to 1024 bits. With
`rustcrypto`, the RustCrypto RC2 engine is cross-checked against the table
engine on pseudorandom keys, effective sizes and blocks. A test requires every
engine API to document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_rc_cipher --locked
cargo test -p tc_rc_cipher --locked --all-features
cargo clippy -p tc_rc_cipher --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_rc_cipher --check
cargo doc -p tc_rc_cipher --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_rc_cipher --list --locked
cargo publish -p tc_rc_cipher --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
