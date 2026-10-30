//! Threefish tweakable single-block ciphers.
//!
//! The 256-, 512- and 1024-bit variants require a block-sized key and an
//! optional 16-byte tweak. An absent tweak is equivalent to sixteen zero bytes.
//!
//! [`ThreefishEngine`] and its aliases use [`ThreefishPortableEngine`], a
//! portable engine after Bouncy Castle. The `rustcrypto` feature adds
//! `ThreefishRustCryptoEngine`, backed by RustCrypto's `threefish` crate,
//! which `ThreefishEngine` then uses. The `alloc` feature adds
//! `ThreefishParamsOwned`, which owns its key and tweak and wipes them on
//! drop.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod cipher;
mod engine;
mod params;
mod portable_engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod traits;

pub use engine::{Threefish256Engine, Threefish512Engine, Threefish1024Engine, ThreefishEngine};
#[cfg(feature = "alloc")]
pub use params::ThreefishParamsOwned;
pub use params::ThreefishParamsRef;
pub use portable_engine::ThreefishPortableEngine;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::ThreefishRustCryptoEngine;
pub use traits::ThreefishParams;

/// Fixed tweak length in bytes.
pub const TWEAK_BYTES: usize = 16;
/// Threefish-256 display name.
pub const THREEFISH_256_ALGO_NAME: &str = "Threefish-256";
/// Threefish-512 display name.
pub const THREEFISH_512_ALGO_NAME: &str = "Threefish-512";
/// Threefish-1024 display name.
pub const THREEFISH_1024_ALGO_NAME: &str = "Threefish-1024";
