# Changelog

All notable changes to `tc_block_padding` are documented in this file.

## 0.1.0 - 2026-09-29

Initial release.

### Added

- The `BlockCipherPadding` trait: `add_padding` fills the end of a message's
  final block and returns the number of padding bytes, and `pad_count` reports
  how many bytes to remove from a decrypted final block. The trait is usable
  as a trait object.
- `Pkcs7Padding`, `Iso7816d4Padding`, `X923Padding`, `TbcPadding` and
  `ZeroBytePadding`, each stateless with `const fn new`, and
  `Iso10126Padding`, behind the default-off `rand_core` feature, which takes
  the generator it draws its filler from at construction and returns it
  through `into_inner`.
- `PaddingError` with `PositionOutOfRange`, `BlockFull`,
  `UnsupportedBlockSize` and `CorruptPadding`. Every scheme except zero-byte
  padding returns `BlockFull` for a full block, since it must add at least one
  byte; PKCS#7, X9.23 and ISO 10126 return `UnsupportedBlockSize` for blocks of
  256 bytes or more; PKCS#7 and ISO 7816-4 verify the whole padding and X9.23
  and ISO 10126 the count byte, returning `CorruptPadding` on failure.
- Constant-time padding and checks with respect to the block contents,
  following Bouncy Castle's masked, branch-free scans. TBC goes further than
  Bouncy Castle: it derives its filler from the message's last bit without
  branching, and counts its trailing run over the whole block where Bouncy
  Castle stops early.
- `Display` for every scheme, writing `"PKCS7"`, `"ISO7816-4"`, `"X9.23"`,
  `"ISO10126-2"`, `"TBC"` or `"ZeroBytePadding"`.
- Tests of padding and removal at each message length, full blocks,
  out-of-range positions, oversized blocks and corrupt padding for every
  scheme; ISO 10126 tests with a fixed generator and a seeded `StdRng`; a test
  that every public API documents whether it is constant or variable time; and
  doctests for every scheme, including an end-to-end AES-CBC example.

### Compatibility

- Requires Rust 1.85 or later for the default build and uses Rust edition
  2024. The `rand_core` feature follows the minimum Rust version of the
  `rand_core` crate, which is 1.85 for `rand_core` 0.10.1; a later `rand_core`
  release may raise it without a `tc_block_padding` release.
- Has no dependencies by default, and depends on `rand_core` 0.10 only with
  `rand_core`.
- The result of `pad_count`, the count and whether the padding was valid, is
  revealed by design; removing padding before the ciphertext is authenticated
  exposes a padding oracle.
- Zero-byte padding cannot tell padding from a message that ends in `0x00`.
  X9.23 and ISO 10126 check only the count byte, and TBC and zero-byte padding
  cannot detect corruption at all.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
