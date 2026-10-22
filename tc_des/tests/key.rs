use tc_des::{is_real_ede_key, is_weak_ede_key, is_weak_key, set_odd_parity};

/// Bouncy Castle's `DesParameters.DES_weak_keys`: 4 weak, then 12 semi-weak.
const BC_WEAK_KEYS: [[u8; 8]; 16] = [
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e],
    [0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1],
    [0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe],
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

/// The three parts of the NIST Triple DES test key; none is weak.
const K1: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const K2: [u8; 8] = [0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01];
const K3: [u8; 8] = [0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23];

fn concat(parts: &[[u8; 8]]) -> Vec<u8> {
    parts.concat()
}

fn flip_parity(part: [u8; 8]) -> [u8; 8] {
    part.map(|byte| byte ^ 1)
}

#[test]
fn every_bouncy_castle_weak_and_semi_weak_key_is_weak() {
    for key in BC_WEAK_KEYS {
        assert!(is_weak_key(&key), "{key:02x?}");
    }
}

#[test]
fn a_weak_key_stays_weak_whatever_its_parity_bits() {
    for key in BC_WEAK_KEYS {
        assert!(is_weak_key(&flip_parity(key)), "{key:02x?}");
        for index in 0..8 {
            let mut flipped = key;
            flipped[index] ^= 1;
            assert!(is_weak_key(&flipped), "{flipped:02x?}");
        }
    }
}

#[test]
fn keys_that_differ_from_a_weak_key_outside_the_parity_bits_are_not_weak() {
    for key in [K1, K2, K3, [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]] {
        assert!(!is_weak_key(&key), "{key:02x?}");
    }
    for key in BC_WEAK_KEYS {
        for index in 0..8 {
            for bit in 1..8 {
                let mut changed = key;
                changed[index] ^= 1 << bit;
                assert!(!is_weak_key(&changed), "{changed:02x?}");
            }
        }
    }
}

#[test]
fn odd_parity_gives_every_byte_an_odd_bit_count_and_keeps_its_other_bits() {
    let mut bytes: Vec<u8> = (0..=255).collect();
    set_odd_parity(&mut bytes);
    for (original, byte) in (0..=255u8).zip(bytes) {
        assert_eq!(byte.count_ones() % 2, 1, "{original:02x}");
        assert_eq!(byte & 0xfe, original & 0xfe, "{original:02x}");
    }
}

#[test]
fn setting_odd_parity_again_changes_nothing() {
    for mut key in BC_WEAK_KEYS.into_iter().chain([K1, K2, K3]) {
        let expected = key;
        set_odd_parity(&mut key);
        assert_eq!(key, expected);
        let mut flipped = flip_parity(key);
        set_odd_parity(&mut flipped);
        assert_eq!(flipped, expected);
    }
}

#[test]
fn a_triple_des_key_is_weak_when_any_of_its_parts_is_weak() {
    let weak = BC_WEAK_KEYS[5];
    assert!(!is_weak_ede_key(&concat(&[K1, K2])));
    assert!(!is_weak_ede_key(&concat(&[K1, K2, K3])));
    assert!(is_weak_ede_key(&concat(&[weak, K2])));
    assert!(is_weak_ede_key(&concat(&[K1, flip_parity(weak)])));
    assert!(is_weak_ede_key(&concat(&[weak, K2, K3])));
    assert!(is_weak_ede_key(&concat(&[K1, weak, K3])));
    assert!(is_weak_ede_key(&concat(&[K1, K2, flip_parity(weak)])));
}

#[test]
fn a_two_key_triple_des_key_is_real_only_when_its_parts_differ_outside_parity() {
    assert!(is_real_ede_key(&concat(&[K1, K2])));
    assert!(!is_real_ede_key(&concat(&[K1, K1])));
    assert!(!is_real_ede_key(&concat(&[K1, flip_parity(K1)])));
}

#[test]
fn a_three_key_triple_des_key_is_real_only_when_every_pair_of_parts_differs() {
    assert!(is_real_ede_key(&concat(&[K1, K2, K3])));
    assert!(!is_real_ede_key(&concat(&[K1, K1, K3])));
    assert!(!is_real_ede_key(&concat(&[K1, K2, K1])));
    assert!(!is_real_ede_key(&concat(&[K1, K2, K2])));
    assert!(!is_real_ede_key(&concat(&[K1, flip_parity(K1), K3])));
    assert!(!is_real_ede_key(&concat(&[K1, K2, flip_parity(K2)])));
}

#[test]
fn triple_des_keys_of_other_lengths_count_as_weak_and_never_as_real() {
    for len in [0, 8, 15, 17, 23, 25, 32] {
        let key = vec![0x5a; len];
        assert!(is_weak_ede_key(&key), "{len}");
        assert!(!is_real_ede_key(&key), "{len}");
    }
}
