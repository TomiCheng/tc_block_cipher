//! Camellia-128, Camellia-192 and Camellia-256 block cipher as specified by
//! RFC 3713.
//!
//! [`CamelliaEngine`] accepts 16-, 24- or 32-byte keys and processes 16-byte
//! blocks. Import [`BlockCipherInit`](tc_block_cipher::BlockCipherInit) and
//! [`BlockCipher`](tc_block_cipher::BlockCipher) to initialize and use it.
//!
//! # Example
//!
//! Encrypt one block with the 128-bit key from RFC 3713, then decrypt it:
//!
//! ```
//! use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
//! use tc_camellia::{BLOCK_BYTES, CamelliaEngine};
//!
//! let key = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
//! ];
//! let plaintext = key;
//!
//! let mut encryptor = CamelliaEngine::new();
//! encryptor.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//! let mut ciphertext = [0; BLOCK_BYTES];
//! encryptor.process_block(&plaintext, &mut ciphertext)?;
//!
//! let mut decryptor = CamelliaEngine::new();
//! decryptor.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
//! let mut recovered = [0; BLOCK_BYTES];
//! decryptor.process_block(&ciphertext, &mut recovered)?;
//!
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Backend selection
//!
//! With the `rustcrypto` feature, `CamelliaEngine` delegates to
//! `CamelliaRustCryptoEngine`, backed by the RustCrypto `camellia` crate.
//! Without it, the engine delegates to [`CamelliaTableEngine`], which uses four
//! 256-entry `u32` T-tables. [`CamelliaLightEngine`] uses a single 256-byte
//! S-box instead, for small code and data. Every implementation is also
//! available for direct use when enabled.
//!
//! # Security
//!
//! No backend is **constant time**: key setup and block processing use
//! secret-dependent table lookups. It is unsuitable where cache-timing attacks
//! are in scope. Stored schedules are wiped on drop, but callers remain
//! responsible for their input keys and other copies.
//!
//! This is a block-cipher primitive, not message encryption. It provides no
//! padding, nonce handling, mode or authentication. Use an appropriate
//! authenticated-encryption construction for messages.
//!
//! The crate is `no_std` and requires no allocator.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod cipher;
mod engine;
mod light_engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod table_engine;

pub use engine::CamelliaEngine;
pub use light_engine::CamelliaLightEngine;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::CamelliaRustCryptoEngine;
pub use table_engine::CamelliaTableEngine;

/// Algorithm name returned by every engine's `Display` implementation.
pub const ALGO_NAME: &str = "Camellia";
/// Camellia block length in bytes (128 bits), independent of key size.
pub const BLOCK_BYTES: usize = 16;
/// Accepted key lengths in bytes (128, 192 and 256 bits).
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
