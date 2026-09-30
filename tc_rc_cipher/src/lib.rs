//! RC2, RC5 and RC6 single-block ciphers.
//!
//! - RC2: [`Rc2Engine`] takes a 1- to 128-byte key and an effective key size
//!   of 1 to 1024 bits through [`Rc2Params`]. [`Rc2ParamsRef::new`] uses the
//!   key's full length; [`Rc2ParamsRef::with_effective_key_bits`] picks a size.
//! - RC5: [`Rc532Engine`] and [`Rc564Engine`] take a 1- to 255-byte key and 0
//!   to 255 rounds through [`Rc5Params`], such as [`Rc5ParamsRef`].
//! - RC6: [`Rc6Engine`] is RC6-32/20 and takes a 1- to 255-byte key through any
//!   `KeyParams`, such as `tc_block_cipher::KeyRef`.
//!
//! Everything is exported at the crate root; constants carry the algorithm in
//! their name, such as [`RC2_BLOCK_BYTES`] and [`RC6_MAX_KEY_BYTES`].
//!
//! These ciphers exist for interoperability with existing formats; prefer a
//! modern authenticated cipher for new designs. The `rustcrypto` feature makes
//! [`Rc2Engine`] use RustCrypto's `rc2` crate, and the `alloc` feature adds
//! `Rc2ParamsOwned` and `Rc5ParamsOwned`, which own their key and wipe it on
//! drop.
//!
//! # Example
//!
//! Encrypting the RFC 2268 test block with RC2:
//!
//! ```
//! use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_rc_cipher::{Rc2Engine, Rc2ParamsRef};
//!
//! let mut engine = Rc2Engine::new();
//! engine.init(
//!     CipherDirection::Encrypt,
//!     &Rc2ParamsRef::with_effective_key_bits(&[0; 8], 63),
//! )?;
//! let mut ciphertext = [0; 8];
//! engine.process_block(&[0; 8], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod params;
mod rc2;
mod rc5;
mod rc6;
mod traits;

#[cfg(feature = "alloc")]
pub use params::{Rc2ParamsOwned, Rc5ParamsOwned};
pub use params::{Rc2ParamsRef, Rc5ParamsRef};
#[cfg(feature = "rustcrypto")]
pub use rc2::Rc2RustCryptoEngine;
pub use rc2::{
    ALGO_NAME as RC2_ALGO_NAME, BLOCK_BYTES as RC2_BLOCK_BYTES,
    MAX_EFFECTIVE_KEY_BITS as RC2_MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES as RC2_MAX_KEY_BYTES,
    Rc2Engine, Rc2TableEngine,
};
pub use rc5::{
    DEFAULT_ROUNDS as RC5_DEFAULT_ROUNDS, MAX_KEY_BYTES as RC5_MAX_KEY_BYTES,
    MAX_ROUNDS as RC5_MAX_ROUNDS, RC5_32_ALGO_NAME, RC5_32_BLOCK_BYTES, RC5_64_ALGO_NAME,
    RC5_64_BLOCK_BYTES, Rc532Engine, Rc564Engine,
};
pub use rc6::{
    ALGO_NAME as RC6_ALGO_NAME, BLOCK_BYTES as RC6_BLOCK_BYTES, MAX_KEY_BYTES as RC6_MAX_KEY_BYTES,
    ROUNDS as RC6_ROUNDS, Rc6Engine,
};
pub use traits::{Rc2Params, Rc5Params};
