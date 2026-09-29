//! Block cipher padding schemes: PKCS#7, ISO 7816-4, ANSI X9.23, TBC, zero
//! byte and, with the `rand_core` feature, ISO 10126.
//!
//! ECB and CBC encrypt whole blocks only. A padding scheme fills the end of a
//! message's final block before encryption and, after decryption, reports how
//! many trailing bytes to remove. Every scheme implements
//! [`BlockCipherPadding`] and works on one block at a time; none of them
//! touches a cipher, so they pair with any block mode.
//!
//! # Example
//!
//! AES-128 in CBC mode with PKCS#7, for a 20-byte message:
//!
//! ```
//! use tc_aes::AesEngine;
//! use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_modes::{FixedCbcBlockCipher, KeyWithIvRef};
//! use tc_block_padding::{BlockCipherPadding, Pkcs7Padding};
//!
//! let (key, iv) = ([0x42; 16], [0x24; 16]);
//! let params = KeyWithIvRef::new(&key, &iv);
//! let message = b"twenty byte message!";
//!
//! // Pad the final partial block: bytes 16..20 hold the message, 12 bytes of
//! // padding follow.
//! let mut data = [0u8; 32];
//! data[..message.len()].copy_from_slice(message);
//! Pkcs7Padding::new().add_padding(&mut data[16..], message.len() - 16)?;
//!
//! let mut cbc = FixedCbcBlockCipher::<_, 16>::new(AesEngine::new());
//! cbc.init(CipherDirection::Encrypt, &params)?;
//! let mut ciphertext = [0u8; 32];
//! for (block, out) in data.chunks_exact(16).zip(ciphertext.chunks_exact_mut(16)) {
//!     cbc.process_block(block, out)?;
//! }
//!
//! // Authenticate the ciphertext before this point in real code.
//! cbc.init(CipherDirection::Decrypt, &params)?;
//! let mut plaintext = [0u8; 32];
//! for (block, out) in ciphertext.chunks_exact(16).zip(plaintext.chunks_exact_mut(16)) {
//!     cbc.process_block(block, out)?;
//! }
//! let count = Pkcs7Padding::new().pad_count(&plaintext[16..])?;
//! assert_eq!(&plaintext[..32 - count], message);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Choosing a scheme
//!
//! - [`Pkcs7Padding`]: PKCS#7, the common default. Every padding byte holds
//!   the count, and removal checks all of them.
//! - [`Iso7816d4Padding`]: ISO 7816-4, a `0x80` marker then zeros, used by
//!   smart cards and several MACs.
//! - [`X923Padding`]: ANSI X9.23, zeros then the count. Only the count is
//!   checked on removal.
//! - `Iso10126Padding`, with the `rand_core` feature: ISO 10126, random bytes
//!   then the count. Only the count is checked. The standard is withdrawn; use
//!   it for compatibility.
//! - [`TbcPadding`]: trailing bit complement, filled with the complement of
//!   the message's last bit.
//! - [`ZeroBytePadding`]: zeros. It cannot tell padding from a message that
//!   itself ends in `0x00`, so use it only where message lengths are known
//!   some other way.
//!
//! # Padding a message
//!
//! Pad only the final block, at the offset where the message ends in it. Every
//! scheme except zero-byte padding must add at least one byte, so when the
//! message fills its last block exactly, append one more block and pad it
//! from offset 0; passing the block length instead returns
//! [`PaddingError::BlockFull`]. After decryption, `pad_count` on the final
//! block gives the number of bytes to drop. PKCS#7, X9.23 and ISO 10126 store
//! the count in one byte and reject blocks of 256 bytes or more.
//!
//! # Security
//!
//! Padding does not authenticate. Deciding whether decrypted data carries
//! valid padding and acting on the answer, even by returning a different
//! error, turns CBC into a padding oracle that recovers plaintext without the
//! key. Authenticate the ciphertext before removing padding, for example with
//! a MAC over it, or use an authenticated-encryption construction instead of
//! a padded mode.
//!
//! Every scheme adds and checks padding in constant time with respect to the
//! block contents. What `pad_count` returns, the count and whether the padding
//! was valid, is revealed by its result; that is inherent to removing padding
//! and is why the ciphertext must be authenticated first.
//!
//! # Features
//!
//! The crate is `no_std`, needs no allocator and has no dependencies by
//! default. The `rand_core` feature adds `Iso10126Padding` and a dependency on
//! `rand_core`, through which the caller supplies the generator.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "rand_core")]
mod iso10126;
mod iso7816;
mod padding_error;
mod pkcs7;
mod tbc;
mod traits;
mod x923;
mod zero;

pub use iso7816::Iso7816d4Padding;
#[cfg(feature = "rand_core")]
pub use iso10126::Iso10126Padding;
pub use padding_error::PaddingError;
pub use pkcs7::Pkcs7Padding;
pub use tbc::TbcPadding;
pub use traits::BlockCipherPadding;
pub use x923::X923Padding;
pub use zero::ZeroBytePadding;
