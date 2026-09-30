use core::fmt;

use tc_block_cipher::KeyParams;

use crate::Rc2Params;
use crate::rc2::{MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES};

/// Borrowed RC2 key and effective key size.
///
/// Nothing is validated here; the engine checks both in `init`. `Debug`
/// prints the key length, never the key.
///
/// # Example
///
/// ```
/// use tc_rc_cipher::{Rc2Params, Rc2ParamsRef};
///
/// let key = [0x42; 16];
/// assert_eq!(Rc2ParamsRef::new(&key).effective_key_bits(), 128);
/// assert_eq!(Rc2ParamsRef::with_effective_key_bits(&key, 40).effective_key_bits(), 40);
/// ```
#[derive(Clone, Copy)]
pub struct Rc2ParamsRef<'a> {
    key: &'a [u8],
    effective_key_bits: usize,
}

impl<'a> Rc2ParamsRef<'a> {
    /// Uses the key's full length as the effective size, or 1024 bits for a key
    /// longer than 128 bytes. Constant time.
    pub const fn new(key: &'a [u8]) -> Self {
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

    /// Uses an explicit effective size in bits. Constant time.
    pub const fn with_effective_key_bits(key: &'a [u8], effective_key_bits: usize) -> Self {
        Self {
            key,
            effective_key_bits,
        }
    }
}

impl KeyParams for Rc2ParamsRef<'_> {
    /// Returns the borrowed key. Constant time.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Rc2Params for Rc2ParamsRef<'_> {
    /// Returns the effective key size in bits. Constant time.
    fn effective_key_bits(&self) -> usize {
        self.effective_key_bits
    }
}

impl fmt::Debug for Rc2ParamsRef<'_> {
    /// Writes the key length and effective size, never the key. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc2ParamsRef")
            .field("key_len", &self.key.len())
            .field("effective_key_bits", &self.effective_key_bits)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn defaults_to_the_full_key_size() {
        let params = Rc2ParamsRef::new(&[0u8; 8]);
        assert_eq!(params.key(), &[0u8; 8]);
        assert_eq!(params.effective_key_bits(), 64);
    }

    #[test]
    fn a_key_longer_than_the_maximum_defaults_to_the_maximum_effective_size() {
        let params = Rc2ParamsRef::new(&[0u8; MAX_KEY_BYTES + 1]);
        assert_eq!(params.effective_key_bits(), MAX_EFFECTIVE_KEY_BITS);
    }

    #[test]
    fn accepts_an_explicit_effective_key_size_without_validation() {
        let params = Rc2ParamsRef::with_effective_key_bits(&[], 0);
        assert_eq!(params.key(), &[] as &[u8]);
        assert_eq!(params.effective_key_bits(), 0);
    }

    #[test]
    fn debug_redacts_the_key() {
        let params = Rc2ParamsRef::with_effective_key_bits(&[0xff; 8], 40);
        assert_eq!(
            format!("{params:?}"),
            "Rc2ParamsRef { key_len: 8, effective_key_bits: 40 }"
        );
    }
}
