# tc_block_modes

[![crates.io](https://img.shields.io/crates/v/tc_block_modes.svg)](https://crates.io/crates/tc_block_modes)
[![docs.rs](https://docs.rs/tc_block_modes/badge.svg)](https://docs.rs/tc_block_modes)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

ECB, CBC, CFB, OFB and CTR modes of operation for block ciphers. Every mode
wraps an engine that implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits, such as
[`tc_aes`](https://crates.io/crates/tc_aes), and is itself a block cipher: it
is initialized with a key and an IV and transforms one segment per call.
Ported from Bouncy Castle C#.

The crate is `no_std`, needs no allocator by default and contains no `unsafe`
code. It depends on `tc_block_cipher` and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024), with or without the `alloc`
feature.

## Types

- `EcbBlockCipher` — ECB, every block on its own.
- `FixedCbcBlockCipher`, `CbcBlockCipher` (`alloc`) — CBC over whole blocks.
- `FixedCfbBlockCipher`, `CfbBlockCipher` (`alloc`) — CFB with a segment from
  one byte up to one block.
- `FixedOfbBlockCipher`, `OfbBlockCipher` (`alloc`) — OFB with a segment from
  one byte up to one block.
- `FixedCtrBlockCipher`, `CtrBlockCipher` (`alloc`) — CTR, which Bouncy Castle
  calls SIC (`SicBlockCipher`).
- `KeyWithIvRef`, `KeyWithIvFixed`, `KeyWithIvOwned` (`alloc`) — key and IV
  parameters that borrow, or own and wipe, their bytes.
- `BlockModeError`, `BlockModeInitError` — processing and initialization
  errors that wrap the engine's.

The `Fixed*` forms take the block size, and the CFB or OFB segment size in
bytes, as const generics and keep their state inline; initialization rejects an
engine whose block size differs. The runtime-sized forms size their state from
the engine and take the CFB or OFB feedback size in bits.

CBC takes an IV of exactly one block. CFB and OFB take up to one block and
right-align a shorter IV over zeros, as in FIPS 81, so an empty IV is all
zeros. CTR fills the leading bytes of its counter block with the IV and may
leave at most `min(8, block / 2)` bytes of counter, so AES takes an IV of 8 to
16 bytes. A rejected `init` returns `BlockModeInitError` and keeps the
previous IV and chaining state.

`process_block` transforms the first segment of the input, returns its length
and leaves any longer tail of the output untouched; it returns
`BlockModeError::NotInitialised` before `init` and `BufferTooShort` for a
buffer shorter than a segment, without changing the mode. There is no padding:
ECB and CBC take whole blocks, while CFB, OFB and CTR finish a partial segment
through a segment-sized buffer. `Display` writes the engine's name and the
mode, such as `"AES/CBC"`, `"AES/CFB8"` or `"AES/CTR"`.

OpenPGP CFB, GOFB, KCTR and a byte-oriented stream interface for CTR are not
ported yet.

## Traits

- `BlockCipherMode` — restarts a mode from its IV and exposes the wrapped
  engine; implemented by every mode.
- `IvParams` — the IV a parameter type provides alongside the engine's
  `KeyParams`.

## Features

- `alloc` (off by default) — adds the runtime-sized modes and `KeyWithIvOwned`;
  does not require the standard library.

## Usage

```toml
[dependencies]
tc_block_modes = "0.1.0"
tc_block_cipher = "0.1.0"
tc_aes = "0.1.0"
```

```rust
use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_modes::{FixedCbcBlockCipher, KeyWithIvRef};

let (key, iv) = ([0x42; 16], [0x24; 16]); // a fresh, unpredictable IV per message
let mut cbc = FixedCbcBlockCipher::<_, 16>::new(AesEngine::new());
cbc.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv)).expect("valid key and IV");
let mut ciphertext = [0; 16];
cbc.process_block(b"one single block", &mut ciphertext).expect("initialized, whole block");
```

The crate and type documentation carry executable examples for every mode.

## Security

No mode authenticates, so altered ciphertext goes undetected. Protect messages
with an authenticated-encryption construction, or add a MAC over the
ciphertext.

The IV decides the confidentiality of every mode here. CBC and CFB need a fresh,
unpredictable IV for every message; OFB and CTR need one that never repeats
under a key, and a CTR counter block must never repeat either. The CTR counter
spans the whole block and carries into the IV bytes, so keep each message below
`2^(8 * counter bytes)` blocks: 64 GiB for AES with a 12-byte IV.

The modes add only data-independent XORs, copies and a branch-free counter
increment, so each call is constant time exactly when the engine is.
`tc_aes::AesEngine`, for example, is constant time with AES-NI or its
`rustcrypto` feature and variable time otherwise.

Every mode wipes its IV, its feedback register or counter, and its last
chaining or keystream block on drop; the engine wipes its own key schedule.
Wiping does not reach the caller's buffers, copies left in registers and on the
stack, or a value that is leaked or forgotten.

## Validation

Every mode is tested against the NIST SP 800-38A AES-128 vectors, including
CFB8, in both directions and in both its fixed-size and runtime-sized forms.
Contract tests cover the IV rules, the CTR counter carry, feedback-size
validation, reset, direction handling, state kept across a rejected `init`,
errors on short buffers and preserved output tails. A test requires every
public API to document whether it is constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_block_modes --locked
cargo test -p tc_block_modes --locked --features alloc
cargo clippy -p tc_block_modes --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_block_modes --check
cargo doc -p tc_block_modes --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_block_modes --list --locked
cargo publish -p tc_block_modes --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
