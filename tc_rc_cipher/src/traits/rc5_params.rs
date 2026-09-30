use tc_block_cipher::KeyParams;

/// Supplies an RC5 key and public round count.
///
/// Timing is implementation-defined; implementations should avoid secret-dependent
/// work when returning the key and parameters.
pub trait Rc5Params: KeyParams {
    /// Returns the round count. Timing is implementation-defined.
    fn rounds(&self) -> usize;
}
