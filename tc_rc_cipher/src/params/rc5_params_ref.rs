use crate::Rc5Params;
use core::fmt;
use core::fmt::{Debug, Formatter};
use tc_block_cipher::KeyParams;

/// Borrowed RC5 key and round count.
///
/// Nothing is validated here; the engine checks both in `init`. `Debug`
/// prints the key length, never the key.
///
/// # Example
///
/// ```
/// use tc_rc_cipher::{RC5_DEFAULT_ROUNDS, Rc5Params, Rc5ParamsRef};
///
/// let key = [0x42; 16];
/// assert_eq!(Rc5ParamsRef::new(&key, 16).rounds(), 16);
/// assert_eq!(Rc5ParamsRef::with_default_rounds(&key).rounds(), RC5_DEFAULT_ROUNDS);
/// ```
#[derive(Clone, Copy)]
pub struct Rc5ParamsRef<'a> {
    key: &'a [u8],
    rounds: usize,
}

impl<'a> Rc5ParamsRef<'a> {
    /// Creates RC5 parameters with an explicit round count. Constant time.
    pub const fn new(key: &'a [u8], rounds: usize) -> Self {
        Self { key, rounds }
    }

    /// Creates RC5 parameters with the standard twelve rounds. Constant time.
    pub const fn with_default_rounds(key: &'a [u8]) -> Self {
        Self::new(key, crate::rc5::DEFAULT_ROUNDS)
    }
}

impl KeyParams for Rc5ParamsRef<'_> {
    /// Borrows the key without inspecting it. Constant time.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Rc5Params for Rc5ParamsRef<'_> {
    /// Returns the stored public round count. Constant time.
    fn rounds(&self) -> usize {
        self.rounds
    }
}

impl Debug for Rc5ParamsRef<'_> {
    /// Writes public parameters without revealing key bytes.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc5ParamsRef")
            .field("key_len", &self.key.len())
            .field("rounds", &self.rounds)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn exposes_explicit_and_default_round_counts() {
        assert_eq!(Rc5ParamsRef::new(&[0u8; 8], 16).rounds(), 16);
        assert_eq!(
            Rc5ParamsRef::with_default_rounds(&[0u8; 8]).rounds(),
            crate::rc5::DEFAULT_ROUNDS
        );
    }

    #[test]
    fn debug_redacts_the_key() {
        let params = Rc5ParamsRef::new(&[0xff; 8], 16);
        assert_eq!(
            format!("{params:?}"),
            "Rc5ParamsRef { key_len: 8, rounds: 16 }"
        );
    }
}
