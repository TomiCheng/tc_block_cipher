//! The GOST 28147 parameter contract.

use tc_block_cipher::KeyParams;

/// Supplies a GOST 28147 key and the S-box to run it under.
///
/// Timing is implementation-defined; implementations should avoid
/// secret-dependent work when returning the borrowed bytes.
pub trait Gost28147Params: KeyParams {
    /// Returns the S-box bytes. Timing is implementation-defined.
    fn s_box(&self) -> &[u8];
}
