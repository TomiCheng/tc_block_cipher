use core::fmt;

/// An engine's own parameters and an initialization vector, both borrowed, as
/// Bouncy Castle's `ParametersWithIV`.
///
/// No allocation or copying, so it needs no `alloc` feature: the fixed-size
/// modes take it without an allocator. A mode keeps the IV and initializes its
/// engine with the inner parameters alone, so an engine whose parameters are
/// more than a key, such as RC2 with its effective key bits, works in every
/// mode with an IV. `TParams` may be unsized, such as a trait object. Nothing
/// is validated until the mode is initialized.
///
/// It does not implement [`IvParams`](crate::IvParams): a mode takes it
/// through an implementation of its own, which strips the IV, rather than the
/// one over [`IvParams`](crate::IvParams), which hands the whole parameters to
/// the engine. A wrapper whose inner cipher is itself a mode passes it down
/// whole.
///
/// The caller owns both values and is responsible for wiping them; dropping
/// this view modifies neither. `Debug` prints the inner parameters as their
/// type does and only the IV's length. `ParamsWithIvOwned`, with the `alloc`
/// feature, owns them instead.
///
/// Constant time: no method inspects the IV.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{FixedCbcBlockCipher, ParamsWithIvRef};
/// use tc_rc_cipher::{Rc2Engine, Rc2ParamsRef};
///
/// // RC2 with 40 effective key bits, in CBC, with no allocator
/// let (key, iv) = ([0x42; 16], [0x24; 8]);
/// let rc2 = Rc2ParamsRef::with_effective_key_bits(&key, 40);
/// let mut mode = FixedCbcBlockCipher::<_, 8>::new(Rc2Engine::new());
/// mode.init(CipherDirection::Encrypt, &ParamsWithIvRef::new(&rc2, &iv))?;
/// let mut ciphertext = [0; 8];
/// mode.process_block(b"8 bytes!", &mut ciphertext)?;
///
/// mode.init(CipherDirection::Decrypt, &ParamsWithIvRef::new(&rc2, &iv))?;
/// let mut recovered = [0; 8];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"8 bytes!");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct ParamsWithIvRef<'a, TParams: ?Sized> {
    params: &'a TParams,
    iv: &'a [u8],
}

impl<'a, TParams: ?Sized> ParamsWithIvRef<'a, TParams> {
    /// Borrows `params` and `iv` without copying or validating them.
    /// Constant time: does not inspect either.
    pub const fn new(params: &'a TParams, iv: &'a [u8]) -> Self {
        Self { params, iv }
    }

    /// Returns the inner parameters, which a mode gives its engine.
    /// Constant time.
    pub const fn params(&self) -> &'a TParams {
        self.params
    }

    /// Returns the IV bytes, which a mode keeps.
    /// Constant time: does not inspect the IV.
    pub const fn iv(&self) -> &'a [u8] {
        self.iv
    }
}

impl<TParams: ?Sized> Clone for ParamsWithIvRef<'_, TParams> {
    /// Copies the two borrows. Constant time.
    fn clone(&self) -> Self {
        *self
    }
}

impl<TParams: ?Sized> Copy for ParamsWithIvRef<'_, TParams> {}

impl<TParams: fmt::Debug + ?Sized> fmt::Debug for ParamsWithIvRef<'_, TParams> {
    /// Writes the inner parameters as their `Debug` does and the IV's length,
    /// never its bytes. Constant time with respect to the IV, which it never
    /// reads; the inner `Debug` and the formatter set the rest of its timing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParamsWithIvRef")
            .field("params", &self.params)
            .field("iv_len", &self.iv.len())
            .finish()
    }
}
