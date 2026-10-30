//! Threefish-256 after Bouncy Castle's `Threefish256Cipher`.

use super::{eject, fixed, inject};

const ROUNDS: usize = 72;

/// Rotation constants from Skein 1.3, as two groups of four rounds.
#[rustfmt::skip]
const R: [[[u32; 2]; 4]; 2] = [
    [[14, 16], [52, 57], [23, 40], [5, 37]],
    [[25, 33], [46, 12], [58, 22], [32, 32]],
];

/// Four rounds with the word permutation folded into the pairs. Constant time.
#[inline(always)]
fn mix4(b: &mut [u64; 4], r: &[[u32; 2]; 4]) {
    mix!(b, r[0][0], 0, 1);
    mix!(b, r[0][1], 2, 3);

    mix!(b, r[1][0], 0, 3);
    mix!(b, r[1][1], 2, 1);

    mix!(b, r[2][0], 0, 1);
    mix!(b, r[2][1], 2, 3);

    mix!(b, r[3][0], 0, 3);
    mix!(b, r[3][1], 2, 1);
}

/// Inverts [`mix4`]. Constant time.
#[inline(always)]
fn unmix4(b: &mut [u64; 4], r: &[[u32; 2]; 4]) {
    unmix!(b, r[3][0], 0, 3);
    unmix!(b, r[3][1], 2, 1);

    unmix!(b, r[2][0], 0, 1);
    unmix!(b, r[2][1], 2, 3);

    unmix!(b, r[1][0], 0, 3);
    unmix!(b, r[1][1], 2, 1);

    unmix!(b, r[0][0], 0, 1);
    unmix!(b, r[0][1], 2, 3);
}

/// Encrypts one block in place. Constant time: rotations, pairs and schedule
/// offsets follow the public round number.
pub(crate) fn encrypt(kw: &[u64], t: &[u64; 5], block: &mut [u64]) {
    let (kw, b) = fixed::<4, 9>(kw, block);
    inject(b, kw, t, 0, 0, 0);
    for d in (1..ROUNDS / 4).step_by(2) {
        let (dm5, dm3) = (d % 5, d % 3);
        mix4(b, &R[0]);
        inject(b, kw, t, dm5, dm3, d);
        mix4(b, &R[1]);
        inject(b, kw, t, dm5 + 1, dm3 + 1, d + 1);
    }
}

/// Decrypts one block in place. Constant time: rotations, pairs and schedule
/// offsets follow the public round number.
pub(crate) fn decrypt(kw: &[u64], t: &[u64; 5], block: &mut [u64]) {
    let (kw, b) = fixed::<4, 9>(kw, block);
    for d in (1..ROUNDS / 4).step_by(2).rev() {
        let (dm5, dm3) = (d % 5, d % 3);
        eject(b, kw, t, dm5 + 1, dm3 + 1, d + 1);
        unmix4(b, &R[1]);
        eject(b, kw, t, dm5, dm3, d);
        unmix4(b, &R[0]);
    }
    eject(b, kw, t, 0, 0, 0);
}
