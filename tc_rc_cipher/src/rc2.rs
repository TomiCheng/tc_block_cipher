mod cipher;
mod engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod table_engine;

pub use engine::Rc2Engine;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::Rc2RustCryptoEngine;
pub use table_engine::Rc2TableEngine;

/// RC2 block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// Maximum RC2 key length in bytes.
pub const MAX_KEY_BYTES: usize = 128;
/// Maximum RC2 effective key size in bits.
pub const MAX_EFFECTIVE_KEY_BITS: usize = 1024;

/// Algorithm display name.
pub const ALGO_NAME: &str = "RC2";
