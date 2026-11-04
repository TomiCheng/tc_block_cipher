//! Blowfish single-block encryption with 4- to 56-byte keys and 8-byte blocks.
//!
//! # Backend selection
//!
//! With the `rustcrypto` feature, [`BlowfishEngine`] delegates to
//! `BlowfishRustCryptoEngine`, backed by the RustCrypto `blowfish` crate.
//! Without it, the engine delegates to [`BlowfishTableEngine`]. Both
//! implementations are also available for direct use when enabled.
//!
//! # Security
//!
//! Variable time: key expansion and processing index key-dependent S-boxes
//! with secret data in both backends. Use only where cache-timing leakage is
//! outside the threat model; no constant-time alternative is provided. Stored
//! P-arrays and S-boxes are wiped on drop, but caller buffers and every
//! register or stack copy are not. No mode, padding or authentication is
//! provided.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod engine;

#[cfg(feature = "rustcrypto")]
pub use engine::BlowfishRustCryptoEngine;
pub use engine::{BlowfishEngine, BlowfishTableEngine};

/// Blowfish block length in bytes.
pub const BLOCK_BYTES: usize = 8;
/// Minimum Blowfish key length in bytes.
pub const MIN_KEY_BYTES: usize = 4;
/// Maximum Blowfish key length in bytes.
pub const MAX_KEY_BYTES: usize = 56;
/// Algorithm name written by the engine.
pub const ALGO_NAME: &str = "Blowfish";
