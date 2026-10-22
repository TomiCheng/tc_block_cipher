//! Weak-key and parity helpers for code that generates DES and Triple DES keys.

use crate::{EDE2_KEY_BYTES, EDE3_KEY_BYTES};

const DES_KEY_BYTES: usize = 8;

/// Masks out the parity bit, the low bit of each key byte.
const PARITY_MASK: u8 = 0xfe;

/// The 4 weak and 12 semi-weak keys from Schneier, Applied Cryptography,
/// p. 281, in the order Bouncy Castle lists them.
const WEAK_KEYS: [[u8; DES_KEY_BYTES]; 16] = [
    // Weak keys.
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e],
    [0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1],
    [0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe],
    // Semi-weak keys.
    [0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe],
    [0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1],
    [0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1],
    [0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe],
    [0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e],
    [0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe],
    [0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01],
    [0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e],
    [0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01],
    [0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e],
    [0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01],
    [0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1],
];

/// Returns whether `key` is one of the 4 weak or 12 semi-weak DES keys.
///
/// Parity bits are ignored: two keys that differ only in the low bit of their
/// bytes are the same DES key, so both are weak or neither is. Bouncy Castle's
/// `DesParameters.IsWeakKey` compares whole bytes instead.
///
/// Constant time: every table entry and every key byte is compared, without
/// returning early on a match.
pub fn is_weak_key(key: &[u8; DES_KEY_BYTES]) -> bool {
    weak_flag(key) == 1
}

/// Returns whether any 8-byte part of a 16- or 24-byte Triple DES key is weak
/// or semi-weak, as [`is_weak_key`] decides it. Any other length counts as
/// weak, so a malformed key never passes the check.
///
/// Constant time with respect to the key bytes; the length is treated as
/// public.
pub fn is_weak_ede_key(key: &[u8]) -> bool {
    if key.len() != EDE2_KEY_BYTES && key.len() != EDE3_KEY_BYTES {
        return true;
    }
    let mut weak = 0;
    for part in parts(key) {
        weak |= weak_flag(part);
    }
    weak == 1
}

/// Sets the low bit of every byte so that each byte has an odd number of set
/// bits, as DES keys conventionally do. The other seven bits are unchanged.
///
/// Constant time.
pub fn set_odd_parity(key: &mut [u8]) {
    for byte in key {
        let mut parity = *byte ^ 1;
        parity ^= parity >> 4;
        parity ^= parity >> 2;
        parity ^= parity >> 1;
        *byte ^= parity & 1;
    }
}

/// Returns whether a Triple DES key has distinct parts, so that it does not
/// collapse to single DES: `K1 != K2` for a 16-byte key, and `K1`, `K2` and
/// `K3` pairwise distinct for a 24-byte key. Any other length returns `false`.
///
/// Parts are compared with parity bits ignored, for the same reason as in
/// [`is_weak_key`]. Bouncy Castle's `DesEdeParameters.IsRealEdeKey` compares
/// whole bytes and so accepts parts that differ only in parity.
///
/// Constant time with respect to the key bytes; the length is treated as
/// public.
pub fn is_real_ede_key(key: &[u8]) -> bool {
    let mut parts = parts(key);
    match (key.len(), parts.next(), parts.next(), parts.next()) {
        (EDE2_KEY_BYTES, Some(k1), Some(k2), None) => same_flag(k1, k2) == 0,
        (EDE3_KEY_BYTES, Some(k1), Some(k2), Some(k3)) => {
            (same_flag(k1, k2) | same_flag(k1, k3) | same_flag(k2, k3)) == 0
        }
        _ => false,
    }
}

/// The whole 8-byte parts of `key`, in order. Constant time with respect to
/// the key bytes; it only splits by length.
fn parts(key: &[u8]) -> impl Iterator<Item = &[u8; DES_KEY_BYTES]> {
    key.chunks_exact(DES_KEY_BYTES)
        .filter_map(|part| part.try_into().ok())
}

/// 1 when `key` matches a table entry outside the parity bits, otherwise 0.
/// Constant time: it scans the whole table.
fn weak_flag(key: &[u8; DES_KEY_BYTES]) -> usize {
    let mut weak = 0;
    for entry in &WEAK_KEYS {
        weak |= same_flag(key, entry);
    }
    weak
}

/// 1 when `a` and `b` match outside the parity bits, otherwise 0. Constant
/// time: every byte is compared.
fn same_flag(a: &[u8; DES_KEY_BYTES], b: &[u8; DES_KEY_BYTES]) -> usize {
    let mut diff = 0;
    for (x, y) in a.iter().zip(b) {
        diff |= (x ^ y) & PARITY_MASK;
    }
    // A zero difference borrows to usize::MAX, which shifts down to 1.
    (diff as usize).wrapping_sub(1) >> (usize::BITS - 1)
}
