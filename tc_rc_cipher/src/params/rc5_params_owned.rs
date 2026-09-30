use alloc::vec::Vec;
use core::fmt;

use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Rc5Params;
use crate::rc5::DEFAULT_ROUNDS;

/// Owned RC5 key and round count, wiped on drop.
///
/// Available with the `alloc` feature. Construction takes the vector without
/// copying it. Nothing is validated here; the engine checks both in `init`.
/// Wiping does not erase copies held elsewhere. `Debug` prints the key length,
/// never the key.
///
/// # Example
///
/// ```
/// use tc_rc_cipher::{RC5_DEFAULT_ROUNDS, Rc5Params, Rc5ParamsOwned};
///
/// let params = Rc5ParamsOwned::with_default_rounds(vec![0x42; 16]);
/// assert_eq!(params.rounds(), RC5_DEFAULT_ROUNDS);
/// ```
pub struct Rc5ParamsOwned {
    key: Vec<u8>,
    rounds: usize,
}

impl Rc5ParamsOwned {
    /// Uses an explicit round count. Constant time: moves the vector without
    /// inspecting its bytes.
    pub const fn new(key: Vec<u8>, rounds: usize) -> Self {
        Self { key, rounds }
    }

    /// Uses the standard twelve rounds. Constant time: moves the vector without
    /// inspecting its bytes.
    pub const fn with_default_rounds(key: Vec<u8>) -> Self {
        Self::new(key, DEFAULT_ROUNDS)
    }
}

impl KeyParams for Rc5ParamsOwned {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Rc5Params for Rc5ParamsOwned {
    /// Returns the round count. Constant time.
    fn rounds(&self) -> usize {
        self.rounds
    }
}

impl fmt::Debug for Rc5ParamsOwned {
    /// Writes the key length and round count, never the key. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc5ParamsOwned")
            .field("key_len", &self.key.len())
            .field("rounds", &self.rounds)
            .finish()
    }
}

impl Zeroize for Rc5ParamsOwned {
    /// Overwrites the key with zeros and leaves it empty. Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for Rc5ParamsOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Rc5ParamsOwned {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::vec;

    use super::*;

    #[test]
    fn exposes_explicit_and_default_round_counts() {
        assert_eq!(Rc5ParamsOwned::new(vec![0u8; 8], 16).rounds(), 16);
        assert_eq!(
            Rc5ParamsOwned::with_default_rounds(vec![0u8; 8]).rounds(),
            DEFAULT_ROUNDS
        );
    }

    #[test]
    fn zeroize_clears_the_key() {
        let mut params = Rc5ParamsOwned::new(vec![0xff; 8], 16);
        params.zeroize();
        assert_eq!(params.key(), &[] as &[u8]);
    }

    #[test]
    fn debug_redacts_the_key() {
        let params = Rc5ParamsOwned::new(vec![0xff; 8], 16);
        assert_eq!(
            format!("{params:?}"),
            "Rc5ParamsOwned { key_len: 8, rounds: 16 }"
        );
    }
}
