use tc_block_cipher::KeyParams;

/// Supplies an RC2 key and its effective size.
///
/// Timing is implementation-defined; implementations should return the
/// borrowed key and public size without secret-dependent work.
pub trait Rc2Params: KeyParams {
    /// Returns the effective key size in bits. Timing is implementation-defined.
    fn effective_key_bits(&self) -> usize;
}
