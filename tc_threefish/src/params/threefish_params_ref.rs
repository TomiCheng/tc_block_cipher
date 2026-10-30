//! Borrowed key-and-tweak parameters.

use core::fmt;

use tc_block_cipher::KeyParams;

use crate::ThreefishParams;

/// A borrowed key with an optional borrowed tweak.
///
/// This type does not validate either value; the selected Threefish engine
/// performs validation when it is initialized. Callers with their own parameter
/// type can implement [`KeyParams`] and [`ThreefishParams`] directly.
/// Constant time: construction and access do not inspect key or tweak contents.
#[derive(Clone, Copy)]
pub struct ThreefishParamsRef<'a> {
    key: &'a [u8],
    tweak: Option<&'a [u8]>,
}

impl<'a> ThreefishParamsRef<'a> {
    /// Uses `key` with Threefish's all-zero tweak. Constant time.
    pub const fn new(key: &'a [u8]) -> Self {
        Self { key, tweak: None }
    }

    /// Uses `key` with an explicit tweak. Constant time.
    pub const fn with_tweak(key: &'a [u8], tweak: &'a [u8]) -> Self {
        Self {
            key,
            tweak: Some(tweak),
        }
    }
}

impl KeyParams for ThreefishParamsRef<'_> {
    /// Borrows the key without inspecting it. Constant time.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl ThreefishParams for ThreefishParamsRef<'_> {
    /// Borrows the optional tweak without inspecting it. Constant time.
    fn tweak(&self) -> Option<&[u8]> {
        self.tweak
    }
}

impl fmt::Debug for ThreefishParamsRef<'_> {
    /// Writes public lengths, never key or tweak bytes.
    /// Constant time with respect to secret contents; timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreefishParamsRef")
            .field("key_len", &self.key.len())
            .field("tweak_len", &self.tweak.map(<[u8]>::len))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn exposes_an_absent_or_explicit_tweak() {
        let key = [0u8; 32];
        let tweak = [0u8; 16];
        assert_eq!(ThreefishParamsRef::new(&key).tweak(), None);
        assert_eq!(
            ThreefishParamsRef::with_tweak(&key, &tweak).tweak(),
            Some(&tweak[..])
        );
    }

    #[test]
    fn values_are_left_unchecked_for_the_engine() {
        let params = ThreefishParamsRef::with_tweak(&[], &[]);
        assert_eq!(params.key(), &[] as &[u8]);
        assert_eq!(params.tweak(), Some(&[][..]));
    }

    #[test]
    fn debug_redacts_key_and_tweak_material() {
        let params = ThreefishParamsRef::with_tweak(&[0xa5; 32], &[0x5a; 16]);
        assert_eq!(
            format!("{params:?}"),
            "ThreefishParamsRef { key_len: 32, tweak_len: Some(16) }"
        );
    }
}
