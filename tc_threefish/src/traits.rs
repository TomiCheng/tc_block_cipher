//! The Threefish parameter contract.

use tc_block_cipher::KeyParams;

/// Supplies a Threefish key and its optional tweak.
///
/// Timing is implementation-defined; implementations should avoid
/// secret-dependent work when returning the borrowed bytes.
pub trait ThreefishParams: KeyParams {
    /// Returns a tweak or `None` for the all-zero tweak. Timing is implementation-defined.
    fn tweak(&self) -> Option<&[u8]>;
}
