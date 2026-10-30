//! Owned key-and-tweak parameters.

use alloc::vec::Vec;
use core::fmt;

use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ThreefishParams;

/// An owned key with an optional owned tweak, both wiped on drop.
///
/// Available with the `alloc` feature. Construction takes the vectors without
/// copying them. Nothing is validated here; the engine checks both lengths in
/// `init`. Wiping does not erase copies held elsewhere. `Debug` prints the
/// lengths, never the key or tweak.
///
/// # Example
///
/// ```
/// use tc_threefish::{ThreefishParams, ThreefishParamsOwned};
///
/// let params = ThreefishParamsOwned::with_tweak(vec![0x42; 32], vec![0x11; 16]);
/// assert_eq!(params.tweak(), Some(&[0x11; 16][..]));
/// ```
pub struct ThreefishParamsOwned {
    key: Vec<u8>,
    tweak: Option<Vec<u8>>,
}

impl ThreefishParamsOwned {
    /// Uses `key` with Threefish's all-zero tweak. Constant time: moves the
    /// vector without inspecting its bytes.
    pub const fn new(key: Vec<u8>) -> Self {
        Self { key, tweak: None }
    }

    /// Uses `key` with an explicit tweak. Constant time: moves the vectors
    /// without inspecting their bytes.
    pub const fn with_tweak(key: Vec<u8>, tweak: Vec<u8>) -> Self {
        Self {
            key,
            tweak: Some(tweak),
        }
    }
}

impl KeyParams for ThreefishParamsOwned {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl ThreefishParams for ThreefishParamsOwned {
    /// Returns the stored tweak without copying it. Constant time.
    fn tweak(&self) -> Option<&[u8]> {
        self.tweak.as_deref()
    }
}

impl fmt::Debug for ThreefishParamsOwned {
    /// Writes the key and tweak lengths, never their bytes. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreefishParamsOwned")
            .field("key_len", &self.key.len())
            .field("tweak_len", &self.tweak.as_ref().map(Vec::len))
            .finish()
    }
}

impl Zeroize for ThreefishParamsOwned {
    /// Overwrites the key and tweak with zeros, leaving the key empty and the
    /// tweak absent. Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.tweak.zeroize();
    }
}

impl Drop for ThreefishParamsOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ThreefishParamsOwned {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::vec;

    use super::*;

    #[test]
    fn exposes_an_absent_or_explicit_tweak() {
        assert_eq!(ThreefishParamsOwned::new(vec![0u8; 32]).tweak(), None);
        assert_eq!(
            ThreefishParamsOwned::with_tweak(vec![0u8; 32], vec![0x5a; 16]).tweak(),
            Some(&[0x5a; 16][..])
        );
    }

    #[test]
    fn zeroize_clears_the_key_and_tweak() {
        let mut params = ThreefishParamsOwned::with_tweak(vec![0xff; 32], vec![0xff; 16]);
        params.zeroize();
        assert_eq!(params.key(), &[] as &[u8]);
        assert_eq!(params.tweak(), None);
    }

    #[test]
    fn debug_redacts_key_and_tweak_material() {
        let params = ThreefishParamsOwned::with_tweak(vec![0xa5; 32], vec![0x5a; 16]);
        assert_eq!(
            format!("{params:?}"),
            "ThreefishParamsOwned { key_len: 32, tweak_len: Some(16) }"
        );
    }
}
