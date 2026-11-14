use alloc::vec::Vec;
use core::fmt;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// An engine's own parameters with an owned initialization vector, wiped on
/// drop, as Bouncy Castle's `ParametersWithIV`.
///
/// Available with the `alloc` feature. A mode keeps the IV and initializes its
/// engine with the inner parameters alone, so an engine whose parameters are
/// more than a key, such as RC2 with its effective key bits, works in every
/// mode with an IV. Construction moves both values rather than copying them,
/// and nothing is validated until the mode is initialized.
///
/// It does not implement [`IvParams`](crate::IvParams): a mode takes it
/// through an implementation of its own, which strips the IV, rather than the
/// one over [`IvParams`](crate::IvParams), which hands the whole parameters to
/// the engine. A wrapper whose inner cipher is itself a mode passes it down
/// whole.
///
/// Drop wipes the IV; the inner parameters wipe themselves when their type
/// does. With `TParams: Zeroize`, [`zeroize`](Zeroize::zeroize) wipes both.
/// The IV is not secret, but is wiped to keep one rule. `Debug` prints the
/// inner parameters as their type does and only the IV's length.
///
/// Constant time: no method inspects the IV.
///
/// # Example
///
/// ```
/// use tc_block_cipher::KeyOwned;
/// use tc_block_modes::ParamsWithIvOwned;
///
/// let params = ParamsWithIvOwned::new(KeyOwned::new(vec![0x42; 16]), vec![0x24; 16]);
/// assert_eq!(params.iv(), &[0x24; 16]);
/// ```
pub struct ParamsWithIvOwned<TParams> {
    params: TParams,
    iv: Vec<u8>,
}

impl<TParams> ParamsWithIvOwned<TParams> {
    /// Takes ownership of `params` and `iv` without validating them.
    /// Constant time: moves the values without inspecting them.
    pub const fn new(params: TParams, iv: Vec<u8>) -> Self {
        Self { params, iv }
    }

    /// Returns the inner parameters, which a mode gives its engine.
    /// Constant time.
    pub const fn params(&self) -> &TParams {
        &self.params
    }

    /// Returns the IV bytes without copying them, which a mode keeps.
    /// Constant time: does not inspect the IV.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl<TParams: fmt::Debug> fmt::Debug for ParamsWithIvOwned<TParams> {
    /// Writes the inner parameters as their `Debug` does and the IV's length,
    /// never its bytes. Constant time with respect to the IV, which it never
    /// reads; the inner `Debug` and the formatter set the rest of its timing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParamsWithIvOwned")
            .field("params", &self.params)
            .field("iv_len", &self.iv.len())
            .finish()
    }
}

impl<TParams: Zeroize> Zeroize for ParamsWithIvOwned<TParams> {
    /// Overwrites the inner parameters and the IV. Constant time when the
    /// inner `zeroize` is.
    fn zeroize(&mut self) {
        self.params.zeroize();
        self.iv.zeroize();
    }
}

impl<TParams> Drop for ParamsWithIvOwned<TParams> {
    /// Wipes the IV; the inner parameters are dropped after it and wipe
    /// themselves when their type does. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl<TParams: ZeroizeOnDrop> ZeroizeOnDrop for ParamsWithIvOwned<TParams> {}
