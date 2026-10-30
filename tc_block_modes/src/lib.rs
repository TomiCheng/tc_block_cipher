//! Block-cipher modes of operation: ECB, CBC, CFB, OFB and CTR, and the
//! algorithm-specific OpenPGP CFB, GOST 28147 GCTR (GOFB) and DSTU 7624 KCTR.
//!
//! Each mode wraps an engine that implements the [`tc_block_cipher`] traits
//! and is itself a block cipher: initialize it with
//! [`BlockCipherInit::init`](tc_block_cipher::BlockCipherInit::init), then
//! transform one segment per call with
//! [`BlockCipher::process_block`](tc_block_cipher::BlockCipher::process_block).
//! [`BlockCipherMode`] adds [`reset`](BlockCipherMode::reset) and access to
//! the wrapped engine. Import the traits from `tc_block_cipher`.
//!
//! # Example
//!
//! AES-128 in CBC mode, encrypting and decrypting a two-block message:
//!
//! ```
//! use tc_aes::AesEngine;
//! use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_modes::{FixedCbcBlockCipher, KeyWithIvRef};
//!
//! let key = [0x42; 16];
//! // Use a fresh, unpredictable IV for every message.
//! let iv = [0x24; 16];
//! let params = KeyWithIvRef::new(&key, &iv);
//! let message = *b"two blocks of exactly 32 bytes!!";
//!
//! let mut mode = FixedCbcBlockCipher::<_, 16>::new(AesEngine::new());
//! mode.init(CipherDirection::Encrypt, &params)?;
//! let mut ciphertext = [0; 32];
//! for (block, out) in message.chunks_exact(16).zip(ciphertext.chunks_exact_mut(16)) {
//!     mode.process_block(block, out)?;
//! }
//!
//! mode.init(CipherDirection::Decrypt, &params)?;
//! let mut recovered = [0; 32];
//! for (block, out) in ciphertext.chunks_exact(16).zip(recovered.chunks_exact_mut(16)) {
//!     mode.process_block(block, out)?;
//! }
//! assert_eq!(recovered, message);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Choosing a mode
//!
//! - [`EcbBlockCipher`]: every block independently. Equal plaintext blocks
//!   give equal ciphertext blocks, so use it only for single blocks or as a
//!   building block.
//! - [`FixedCbcBlockCipher`] and `CbcBlockCipher`: CBC. Whole blocks only;
//!   the IV must be unpredictable for every message.
//! - [`FixedCfbBlockCipher`] and `CfbBlockCipher`: CFB with a segment from one
//!   byte (CFB8) up to one block (CFB128 for AES). The IV must be
//!   unpredictable for every message.
//! - [`FixedOfbBlockCipher`] and `OfbBlockCipher`: OFB. The IV must never
//!   repeat under one key.
//! - [`FixedCtrBlockCipher`] and `CtrBlockCipher`: CTR. A counter block must
//!   never repeat under one key.
//! - [`FixedOpenPgpCfbBlockCipher`] and `OpenPgpCfbBlockCipher`: OpenPGP's
//!   CFB variant of RFC 4880, which resynchronizes after the first block and
//!   two bytes. Use it only to read or write OpenPGP data.
//! - [`GofbBlockCipher`]: GOST 28147-89 counter mode (GCTR) over an 8-byte
//!   block. The IV must never repeat under one key.
//! - [`FixedKctrBlockCipher`] and `KctrBlockCipher`: DSTU 7624 counter mode
//!   (KCTR). The IV must never repeat under one key.
//!
//! The `Fixed*` forms take the block size `N` (and, for CFB and OFB, the
//! segment size `S` in bytes) as const generics, keep their state inline and
//! need no allocator; initialization rejects an engine whose block size is not
//! `N`. The runtime-sized forms, available with the `alloc` feature, size
//! their state from the engine and take the CFB and OFB feedback size in bits.
//! GOFB is defined for 8-byte blocks only, so it has one form, which keeps its
//! state inline and rejects any other block size.
//!
//! # Parameters
//!
//! A mode accepts any parameter type that the engine accepts and that also
//! provides the IV through [`IvParams`]. The mode checks the IV and passes the
//! same value on to the engine's `init`.
//!
//! - [`KeyWithIvRef`] borrows a key and an IV without copying or wiping them.
//! - [`KeyWithIvFixed`] owns fixed-size arrays and wipes them on drop.
//! - `KeyWithIvOwned`, available with the `alloc` feature, owns vectors and
//!   wipes them on drop.
//!
//! IV rules depend on the mode:
//!
//! - CBC: exactly one block.
//! - CFB, OFB, OpenPGP CFB, GOFB and KCTR: at most one block. A shorter IV is
//!   right-aligned over zeros, as in FIPS 81, so an empty IV is all zeros.
//!   OpenPGP itself uses the all-zero IV and puts its randomness in a prefix
//!   of the data.
//! - CTR: required. The IV fills the leading bytes of the counter block and
//!   the rest start at zero; it may leave at most `min(8, block / 2)` bytes of
//!   counter, so AES needs 8 to 16 bytes. The counter spans the whole block
//!   and carries into the IV bytes, so keep each message below
//!   `2^(8 * counter bytes)` blocks: 64 GiB for AES with a 12-byte IV.
//!
//! A fixed or all-zero IV defeats the confidentiality of every mode here.
//!
//! # Processing
//!
//! [`block_size`](tc_block_cipher::BlockCipher::block_size) returns the
//! segment each call transforms: the engine block for ECB, CBC, CTR, OpenPGP
//! CFB, GOFB and KCTR, the feedback segment for CFB and OFB. `process_block`
//! transforms the first segment of `input` into `output`, returns its length
//! and leaves any longer tail of `output` untouched. It returns [`BlockModeError::NotInitialised`]
//! before a successful `init` and [`BlockModeError::BufferTooShort`] when
//! either buffer is shorter than a segment; both leave the mode unchanged.
//!
//! There is no padding. ECB and CBC process whole blocks only. The other modes
//! report [`is_partial_block_okay`](BlockCipherMode::is_partial_block_okay):
//! to finish with a partial segment, copy it into a segment-sized buffer,
//! process that, and keep the matching prefix of the output. No mode offers a
//! byte-at-a-time stream interface.
//!
//! A rejected `init` leaves the IV and chaining state of the previous
//! initialization in place; the engine's own state after a rejection is
//! defined by the engine. Every mode except ECB and CBC always initializes the
//! engine for encryption, and OFB, CTR, GOFB and KCTR ignore the requested
//! direction.
//!
//! # Security
//!
//! None of these modes authenticates: ciphertext can be altered without
//! detection. Protect messages with an authenticated-encryption construction,
//! or add a MAC over the ciphertext.
//!
//! The modes add only data-independent XORs, copies and branch-free counter
//! arithmetic, so each call is constant time exactly when the engine is.
//! `tc_aes::AesEngine`, for example, is constant time with AES-NI or its
//! `rustcrypto` feature and variable time otherwise.
//!
//! Each mode wipes its IV, its feedback register or counter, and its last
//! chaining or keystream block on drop; the engine wipes its key schedule as
//! its documentation states. Neither erases the caller's buffers or temporary
//! copies left in registers or on the stack.
//!
//! # Features
//!
//! The crate is `no_std` and requires no allocator by default. Enable `alloc`
//! for the runtime-sized modes and `KeyWithIvOwned`; this does not require the
//! standard library.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod cbc;
mod cfb;
mod ctr;
mod ecb;
mod error;
mod gofb;
mod kctr;
mod ofb;
mod openpgp_cfb;
mod params;
mod traits;

#[cfg(feature = "alloc")]
pub use cbc::CbcBlockCipher;
pub use cbc::FixedCbcBlockCipher;
#[cfg(feature = "alloc")]
pub use cfb::CfbBlockCipher;
pub use cfb::FixedCfbBlockCipher;
#[cfg(feature = "alloc")]
pub use ctr::CtrBlockCipher;
pub use ctr::FixedCtrBlockCipher;
pub use ecb::EcbBlockCipher;
pub use error::BlockModeError;
pub use error::BlockModeInitError;
pub use gofb::GofbBlockCipher;
pub use kctr::FixedKctrBlockCipher;
#[cfg(feature = "alloc")]
pub use kctr::KctrBlockCipher;
pub use ofb::FixedOfbBlockCipher;
#[cfg(feature = "alloc")]
pub use ofb::OfbBlockCipher;
pub use openpgp_cfb::FixedOpenPgpCfbBlockCipher;
#[cfg(feature = "alloc")]
pub use openpgp_cfb::OpenPgpCfbBlockCipher;
#[cfg(feature = "alloc")]
pub use params::KeyWithIvOwned;
pub use params::{KeyWithIvFixed, KeyWithIvRef};
pub use traits::BlockCipherMode;
pub use traits::IvParams;
