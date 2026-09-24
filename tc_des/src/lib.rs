//! Data Encryption Standard (DES) and Triple DES implementations.
//!
//! These algorithms are retained for compatibility with legacy protocols and
//! are not suitable for new designs.
//!
//! # Choosing an engine
//!
//! [`DesEngine`] and [`DesEdeEngine`] pick an engine at compile time: the
//! RustCrypto engines when the `rustcrypto` Cargo feature is enabled,
//! otherwise [`DesTableEngine`] and [`DesEdeTableEngine`]. Every engine is
//! variable time, since each looks up S-boxes with secret data; the RustCrypto
//! engines narrow the cache-timing channel with smaller S-boxes and a
//! branch-free key schedule. For explicit selection, `DesRustCryptoEngine` and
//! `DesEdeRustCryptoEngine` are available with the `rustcrypto` feature.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod cipher;
mod engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod table_engine;

pub use engine::{DesEdeEngine, DesEngine};
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::{DesEdeRustCryptoEngine, DesRustCryptoEngine};
pub use table_engine::{DesEdeTableEngine, DesTableEngine};

/// DES and Triple DES block length in bytes.
pub const BLOCK_BYTES: usize = 8;

/// Algorithm name returned by every DES engine's `Display` implementation.
pub const DES_ALGO_NAME: &str = "DES";
/// Accepted DES key lengths in bytes: 64 encoded bits, 56 of them effective.
pub const DES_KEY_BYTES: [usize; 1] = [8];

/// Algorithm name returned by every Triple DES engine's `Display`
/// implementation.
pub const DES_EDE_ALGO_NAME: &str = "DESede";
/// Encoded key length for two-key Triple DES (`K1, K2, K1`).
pub const EDE2_KEY_BYTES: usize = 16;
/// Encoded key length for three-key Triple DES (`K1, K2, K3`).
pub const EDE3_KEY_BYTES: usize = 24;
/// Accepted Triple DES key lengths in bytes.
pub const DES_EDE_KEY_BYTES: [usize; 2] = [EDE2_KEY_BYTES, EDE3_KEY_BYTES];
