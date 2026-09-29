# tc_block_padding

[![crates.io](https://img.shields.io/crates/v/tc_block_padding.svg)](https://crates.io/crates/tc_block_padding)
[![docs.rs](https://docs.rs/tc_block_padding/badge.svg)](https://docs.rs/tc_block_padding)
[![CI](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_block_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Padding schemes for block cipher modes that process whole blocks, such as ECB
and CBC in [`tc_block_modes`](https://crates.io/crates/tc_block_modes):
PKCS#7, ISO 7816-4, ANSI X9.23, TBC, zero-byte and, with the `rand_core`
feature, ISO 10126. Each scheme pads the final block of a message before
encryption and reports how many bytes to remove after decryption. Ported from
Bouncy Castle C#.

The crate is `no_std`, needs no allocator, contains no `unsafe` code and has
no dependencies by default; the `rand_core` feature adds
[`rand_core`](https://crates.io/crates/rand_core).

Requires Rust 1.85 or later (edition 2024) for the default build. The optional
`rand_core` feature follows the minimum Rust version of the `rand_core` crate
instead, which is 1.85 for `rand_core` 0.10.1.

## Types

- `Pkcs7Padding` — PKCS#7; every padding byte holds the count, and removal
  checks them all.
- `Iso7816d4Padding` — ISO 7816-4; a `0x80` marker followed by zeros.
- `X923Padding` — ANSI X9.23; zeros followed by the count.
- `Iso10126Padding` (`rand_core`) — ISO 10126; random bytes followed by the
  count.
- `TbcPadding` — trailing bit complement; every padding byte is the complement
  of the message's last bit.
- `ZeroBytePadding` — zeros; it cannot tell padding from a message that ends in
  `0x00`.
- `PaddingError` — why a block could not be padded or its padding removed.

Pad only the final block, at the offset where the message ends in it. Every
scheme except zero-byte padding adds at least one byte, so a message that fills
its last block exactly needs one more block, padded from offset 0; padding a
full block returns `PaddingError::BlockFull`. PKCS#7, X9.23 and ISO 10126 store
the count in one byte and return `UnsupportedBlockSize` for blocks of 256 bytes
or more.

`pad_count` returns the number of bytes to drop from a decrypted final block.
PKCS#7 and ISO 7816-4 verify the whole padding, X9.23 and ISO 10126 only the
count byte, and each returns `CorruptPadding` when the check fails; TBC and
zero-byte padding encode no length and cannot detect corruption. `Display`
writes each scheme's name, such as `"PKCS7"` or `"ISO7816-4"`. Every scheme is
stateless except ISO 10126, which owns the generator it is constructed with.

## Traits

- `BlockCipherPadding` — pads a final block and reports how many bytes to
  remove; implemented by every scheme.

## Features

- `rand_core` (off by default) — adds `Iso10126Padding`, which draws its filler
  from a generator the caller supplies; pulls in `rand_core` and its minimum
  Rust version.

## Usage

```toml
[dependencies]
tc_block_padding = "0.1.0"
```

```rust
use tc_block_padding::{BlockCipherPadding, Pkcs7Padding};

let mut padding = Pkcs7Padding::new();
let mut block = *b"hello\0\0\0\0\0\0\0\0\0\0\0"; // the final 16-byte block
assert_eq!(padding.add_padding(&mut block, 5), Ok(11));
assert_eq!(&block[5..], [11; 11]);
assert_eq!(padding.pad_count(&block), Ok(11)); // after decryption
```

The crate documentation carries an end-to-end AES-CBC example and executable
examples for every scheme.

## Security

Padding does not authenticate. Deciding whether decrypted data carries valid
padding and acting on the answer, even by returning a different error, turns
CBC into a padding oracle that recovers plaintext without the key.
Authenticate the ciphertext before removing padding, for example with a MAC
over it, or use an authenticated-encryption construction instead of a padded
mode.

Every scheme adds and checks padding in constant time with respect to the block
contents, and TBC derives its filler without branching on the message. What
`pad_count` returns, the count and whether the padding was valid, is revealed
by its result; that is inherent to removing padding and is why the ciphertext
must be authenticated first. ISO 10126 also takes the generator's own time.

## Validation

Every scheme is tested for padding and removal at each message length, full
blocks, out-of-range positions and corrupt padding, and the count-byte schemes
for oversized blocks. ISO 10126 is tested with a fixed generator and with a
seeded `StdRng`. A test requires every public API to document whether it is
constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_block_padding --locked
cargo test -p tc_block_padding --locked --features rand_core
cargo clippy -p tc_block_padding --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_block_padding --check
cargo doc -p tc_block_padding --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_block_padding --list --locked
cargo publish -p tc_block_padding --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
