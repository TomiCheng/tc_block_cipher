//! Owned key-and-S-box parameters.

use alloc::vec::Vec;
use core::fmt;

use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Gost28147Params, s_box};

/// An owned key paired with an owned S-box, both wiped on drop.
///
/// Available with the `alloc` feature. Construction takes the vectors without
/// copying them; [`new`](Self::new) copies [`s_box::DEFAULT`] into a new
/// vector. Nothing is validated here; the engine checks both lengths in
/// `init`. The S-box may itself be secret in some profiles, so it is wiped
/// with the key. Wiping does not erase copies held elsewhere. `Debug` prints
/// the lengths, never the key or table.
///
/// # Example
///
/// ```
/// use tc_gost28147::{Gost28147Params, Gost28147ParamsOwned, s_box};
///
/// let params = Gost28147ParamsOwned::with_s_box(vec![0x42; 32], s_box::E_A.to_vec());
/// assert_eq!(params.s_box(), s_box::E_A);
/// ```
pub struct Gost28147ParamsOwned {
    key: Vec<u8>,
    s_box: Vec<u8>,
}

impl Gost28147ParamsOwned {
    /// Pairs `key` with a copy of [`s_box::DEFAULT`]. Constant time: moves the
    /// key without inspecting it and copies a public table.
    pub fn new(key: Vec<u8>) -> Self {
        Self::with_s_box(key, s_box::DEFAULT.to_vec())
    }

    /// Pairs `key` with `s_box`, which the engine will check. Constant time:
    /// moves the vectors without inspecting their bytes.
    pub const fn with_s_box(key: Vec<u8>, s_box: Vec<u8>) -> Self {
        Self { key, s_box }
    }
}

impl KeyParams for Gost28147ParamsOwned {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Gost28147Params for Gost28147ParamsOwned {
    /// Returns the stored table without copying it. Constant time.
    fn s_box(&self) -> &[u8] {
        &self.s_box
    }
}

impl fmt::Debug for Gost28147ParamsOwned {
    /// Writes the key and S-box lengths, never their bytes. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gost28147ParamsOwned")
            .field("key_len", &self.key.len())
            .field("s_box_len", &self.s_box.len())
            .finish()
    }
}

impl Zeroize for Gost28147ParamsOwned {
    /// Overwrites the key and S-box with zeros and leaves them empty. Constant time.
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.s_box.zeroize();
    }
}

impl Drop for Gost28147ParamsOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Gost28147ParamsOwned {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::vec;

    use super::*;

    #[test]
    fn a_bare_key_runs_with_the_default_table() {
        let params = Gost28147ParamsOwned::new(vec![0x5a; 32]);
        assert_eq!(params.key(), &[0x5a; 32]);
        assert_eq!(params.s_box(), s_box::DEFAULT);
    }

    #[test]
    fn zeroize_clears_the_key_and_s_box() {
        let mut params = Gost28147ParamsOwned::with_s_box(vec![0xff; 32], vec![0xff; 128]);
        params.zeroize();
        assert_eq!(params.key(), &[] as &[u8]);
        assert_eq!(params.s_box(), &[] as &[u8]);
    }

    #[test]
    fn debug_redacts_both_key_and_s_box_material() {
        let params = Gost28147ParamsOwned::with_s_box(vec![0xa5; 32], vec![0x5a; 128]);
        assert_eq!(
            format!("{params:?}"),
            "Gost28147ParamsOwned { key_len: 32, s_box_len: 128 }"
        );
    }
}
