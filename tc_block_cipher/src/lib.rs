//! Shared interfaces and key containers for single-block ciphers.
//!
//! This crate defines how to initialize a cipher and process a block; it does
//! not implement an encryption algorithm, mode, padding or authentication.
//! Use a concrete engine with these traits, and an authenticated-encryption
//! construction when protecting messages rather than individual blocks.
//!
//! # Using an engine
//!
//! Supply key material through [`KeyParams`], select a [`CipherDirection`],
//! and call [`BlockCipherInit::init`]. After successful initialization, use
//! [`BlockCipher::block_size`] to size buffers and
//! [`BlockCipher::process_block`] to transform one block.
//! Supported key lengths, additional parameters, timing guarantees and state
//! after a rejected initialization are defined by the concrete engine.
//!
//! # Implementing an engine
//!
//! An engine implements [`BlockCipherInit`] for the parameters it accepts and
//! [`BlockCipher`] for processing. The toy engine below XORs four-byte blocks
//! with a four-byte key; it shows the contract and is not a cipher.
//!
//! ```
//! use tc_block_cipher::{
//!     BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyFixed,
//!     KeyParams, KeyRef,
//! };
//!
//! struct Xor4 {
//!     key: Option<[u8; 4]>,
//! }
//!
//! impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Xor4 {
//!     type Error = InitError;
//!
//!     fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
//!         let key = params.key();
//!         let key = key.try_into().map_err(|_| InitError::InvalidKeyLength(key.len()))?;
//!         self.key = Some(key);
//!         Ok(())
//!     }
//! }
//!
//! impl BlockCipher for Xor4 {
//!     type Error = BlockError;
//!
//!     fn block_size(&self) -> usize {
//!         4
//!     }
//!
//!     fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
//!         let key = self.key.ok_or(BlockError::NotInitialised)?;
//!         let (Some(input), Some(output)) = (input.first_chunk::<4>(), output.first_chunk_mut::<4>())
//!         else {
//!             return Err(BlockError::BufferTooShort);
//!         };
//!         for ((out, byte), key) in output.iter_mut().zip(input).zip(key) {
//!             *out = byte ^ key;
//!         }
//!         Ok(4)
//!     }
//! }
//!
//! let mut engine = Xor4 { key: None };
//! let mut output = [0; 4];
//! assert_eq!(
//!     engine.process_block(&[1, 2, 3, 4], &mut output),
//!     Err(BlockError::NotInitialised)
//! );
//!
//! engine.init(CipherDirection::Encrypt, &KeyFixed::new([0xff; 4]))?;
//! assert_eq!(engine.process_block(&[1, 2, 3, 4], &mut output)?, 4);
//! assert_eq!(output, [0xfe, 0xfd, 0xfc, 0xfb]);
//!
//! let short_key = [0; 3];
//! assert_eq!(
//!     engine.init(CipherDirection::Decrypt, &KeyRef::new(&short_key)),
//!     Err(InitError::InvalidKeyLength(3))
//! );
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Choosing key storage
//!
//! - [`KeyRef`] borrows existing bytes without copying or wiping them.
//! - [`KeyFixed`] owns a fixed-size array and wipes its stored key on drop.
//! - `KeyOwned`, available with the `alloc` feature, takes ownership of a
//!   byte vector and wipes its stored key on drop.
//!
//! These containers do not validate algorithm-specific key lengths. Wiping an
//! owned container does not erase caller-held copies, engine key schedules or
//! every temporary copy. Callers must manage those lifetimes separately.
//!
//! # Features
//!
//! The crate is `no_std` and requires no allocator by default. Enable `alloc`
//! for `KeyOwned`; this does not require the standard library.
//!
//! [`InitError`] and [`BlockError`] are reusable error types. The traits use
//! associated error types so an engine may expose more specific failures.
//!
#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod block_error;
mod cipher_direction;
mod init_error;
mod key;
mod traits;

pub use block_error::BlockError;
pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
pub use key::*;
pub use traits::{BlockCipher, BlockCipherInit, KeyParams};
