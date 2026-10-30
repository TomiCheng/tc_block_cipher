//! GOST 28147-89 single-block cipher with caller-selected S-boxes.
//!
//! Keys are 32 bytes and blocks are 8 bytes. The S-box is a parameter;
//! choosing a different table changes the cipher. Standard tables live in
//! [`s_box`]. [`Gost28147ParamsRef`] defaults to [`s_box::DEFAULT`]; custom
//! parameter types implement [`Gost28147Params`].
//!
//! The `alloc` feature adds `Gost28147ParamsOwned`, which owns its key and
//! S-box and wipes them on drop.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod cipher;
mod engine;
mod params;
pub mod s_box;
mod traits;

pub use engine::Gost28147Engine;
#[cfg(feature = "alloc")]
pub use params::Gost28147ParamsOwned;
pub use params::Gost28147ParamsRef;
pub use traits::Gost28147Params;

/// Block length in bytes.
pub const BLOCK_BYTES: usize = 8;
/// Required key length in bytes.
pub const KEY_BYTES: usize = 32;
/// Algorithm display name.
pub const ALGO_NAME: &str = "Gost28147";
