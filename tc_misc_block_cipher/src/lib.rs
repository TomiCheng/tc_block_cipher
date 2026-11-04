//! Less common block ciphers on the [`tc_block_cipher`] traits, ported from
//! Bouncy Castle, one Cargo feature each and none on by default. Each feature
//! adds a module of the same name:
//!
//! - `idea`: IDEA, with a 128-bit key and a 64-bit block.
//! - `noekeon`: Noekeon in direct-key mode, with a 128-bit key and block.
//! - `rijndael`: Rijndael with 128- to 256-bit blocks and keys.
//! - `skipjack`: SKIPJACK, with an 80-bit key and a 64-bit block.
//! - `tea`: TEA and XTEA, with a 128-bit key and a 64-bit block.
//!
//! # Timing
//!
//! Noekeon, TEA and XTEA are constant time with respect to key and block
//! contents: they use only additions, bitwise operations and fixed shifts or
//! rotations.
//! IDEA, Rijndael and SKIPJACK are variable time: IDEA's multiplication branches
//! on secret values and its decryption key setup runs a key-dependent Euclidean
//! loop, Rijndael and SKIPJACK look up tables with secret data, and Rijndael's
//! field multiplication branches on it. Use them only where timing leakage is
//! outside the threat model.
//!
//! Stored schedules are wiped on replacement and drop, but caller buffers and
//! every register or stack copy are not. No mode, padding or authentication is
//! provided.
//!
//! # Example
//!
//! XTEA, with the `tea` feature:
//!
//! ```
//! # #[cfg(feature = "tea")]
//! # {
//! use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
//! use tc_misc_block_cipher::tea::{BLOCK_BYTES, KEY_BYTES, XteaEngine};
//!
//! let key = [0x42; KEY_BYTES];
//! let mut engine = XteaEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
//! let mut ciphertext = [0; BLOCK_BYTES];
//! assert_eq!(
//!     engine.process_block(&[0x11; BLOCK_BYTES], &mut ciphertext),
//!     Ok(BLOCK_BYTES)
//! );
//! # }
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "idea")]
pub mod idea;
#[cfg(feature = "noekeon")]
pub mod noekeon;
#[cfg(feature = "rijndael")]
pub mod rijndael;
#[cfg(feature = "skipjack")]
pub mod skipjack;
#[cfg(feature = "tea")]
pub mod tea;
