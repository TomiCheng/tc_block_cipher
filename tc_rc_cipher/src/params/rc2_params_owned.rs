use alloc::vec::Vec;
use core::fmt;

use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Rc2Params;
use crate::rc2::{MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES};

/// Owned RC2 key and effective key size, wiped on drop.
///
/// Available with the `alloc` feature. Construction takes the vector without
/// copying it. Nothing is validated here; the engine checks both in `init`.
/// Wiping does not erase copies held elsewhere. `Debug` prints the key length,
/// never the key.
///
/// # Example
///
/// ```
/// use tc_rc_cipher::{Rc2Params, Rc2ParamsOwned};
///
/// let params = Rc2ParamsOwned::with_effective_key_bits(vec![0x42; 16], 40);
/// assert_eq!(params.effective_key_bits(), 40);
/// ```
pub struct Rc2ParamsOwned {
    key: Vec<u8>,
    effective_key_bits: usize,
}

impl Rc2ParamsOwned {
    /// Uses the key's full length as the effective size, or 1024 bits for a key
    /// longer than 128 bytes. Constant time: moves the vector without
    /// inspecting its bytes.
    pub fn new(key: Vec<u8>) -> Self {
        let effective_key_bits = if key.len() > MAX_KEY_BYTES {
            MAX_EFFECTIVE_KEY_BITS
        } else {
            key.len() * 8
        };
        Self {
            key,
            effective_key_bits,
        }
    }

    /// Uses an explicit effective size in bits. Constant time: moves the vector
    /// without inspecting its bytes.
    pub const fn with_effective_key_bits(key: Vec<u8>, effective_key_bits: usize) -> Self {
        Self {
            key,
            effective_key_bits,
        }
    }
}

impl KeyParams for Rc2ParamsOwned {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Rc2Params for Rc2ParamsOwned {
    /// Returns the effective key size in bits. Constant time.
    fn effective_key_bits(&self) -> usize {
        self.effective_key_bits
    }
}

impl fmt::Debug for Rc2ParamsOwned {
    /// Writes the key length and effective size, never the key. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc2ParamsOwned")
            .field("key_len", &self.key.len())
            .field("effective_key_bits", &self.effective_key_bits)
            .finish()
    }
}

impl Zeroize for Rc2ParamsOwned {
    /// Overwrites the key with zeros and leaves it empty. Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for Rc2ParamsOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Rc2ParamsOwned {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::vec;

    use super::*;

    #[test]
    fn defaults_to_the_full_key_size() {
        let params = Rc2ParamsOwned::new(vec![0u8; 8]);
        assert_eq!(params.key(), &[0u8; 8]);
        assert_eq!(params.effective_key_bits(), 64);
    }

    #[test]
    fn a_key_longer_than_the_maximum_defaults_to_the_maximum_effective_size() {
        let params = Rc2ParamsOwned::new(vec![0u8; MAX_KEY_BYTES + 1]);
        assert_eq!(params.effective_key_bits(), MAX_EFFECTIVE_KEY_BITS);
    }

    #[test]
    fn accepts_an_explicit_effective_key_size_without_validation() {
        let params = Rc2ParamsOwned::with_effective_key_bits(vec![], 0);
        assert_eq!(params.key(), &[] as &[u8]);
        assert_eq!(params.effective_key_bits(), 0);
    }

    #[test]
    fn zeroize_clears_the_key() {
        let mut params = Rc2ParamsOwned::new(vec![0xff; 8]);
        params.zeroize();
        assert_eq!(params.key(), &[] as &[u8]);
    }

    #[test]
    fn debug_redacts_the_key() {
        let params = Rc2ParamsOwned::with_effective_key_bits(vec![0xff; 8], 40);
        assert_eq!(
            format!("{params:?}"),
            "Rc2ParamsOwned { key_len: 8, effective_key_bits: 40 }"
        );
    }
}
