//! Threefish-1024 after Bouncy Castle's `Threefish1024Cipher`.

use super::{eject, fixed, inject};

const ROUNDS: usize = 80;

/// Rotation constants from Skein 1.3, as two groups of four rounds.
#[rustfmt::skip]
const R: [[[u32; 8]; 4]; 2] = [
    [
        [24, 13, 8, 47, 8, 17, 22, 37],
        [38, 19, 10, 55, 49, 18, 23, 52],
        [33, 4, 51, 13, 34, 41, 59, 17],
        [5, 20, 48, 41, 47, 28, 16, 25],
    ],
    [
        [41, 9, 37, 31, 12, 47, 44, 30],
        [16, 34, 56, 51, 4, 53, 42, 41],
        [31, 44, 47, 46, 19, 42, 44, 25],
        [9, 48, 35, 52, 23, 31, 37, 20],
    ],
];

/// Four rounds with the word permutation folded into the pairs. Constant time.
#[inline(always)]
fn mix4(b: &mut [u64; 16], r: &[[u32; 8]; 4]) {
    mix!(b, r[0][0], 0, 1);
    mix!(b, r[0][1], 2, 3);
    mix!(b, r[0][2], 4, 5);
    mix!(b, r[0][3], 6, 7);
    mix!(b, r[0][4], 8, 9);
    mix!(b, r[0][5], 10, 11);
    mix!(b, r[0][6], 12, 13);
    mix!(b, r[0][7], 14, 15);

    mix!(b, r[1][0], 0, 9);
    mix!(b, r[1][1], 2, 13);
    mix!(b, r[1][2], 6, 11);
    mix!(b, r[1][3], 4, 15);
    mix!(b, r[1][4], 10, 7);
    mix!(b, r[1][5], 12, 3);
    mix!(b, r[1][6], 14, 5);
    mix!(b, r[1][7], 8, 1);

    mix!(b, r[2][0], 0, 7);
    mix!(b, r[2][1], 2, 5);
    mix!(b, r[2][2], 4, 3);
    mix!(b, r[2][3], 6, 1);
    mix!(b, r[2][4], 12, 15);
    mix!(b, r[2][5], 14, 13);
    mix!(b, r[2][6], 8, 11);
    mix!(b, r[2][7], 10, 9);

    mix!(b, r[3][0], 0, 15);
    mix!(b, r[3][1], 2, 11);
    mix!(b, r[3][2], 6, 13);
    mix!(b, r[3][3], 4, 9);
    mix!(b, r[3][4], 14, 1);
    mix!(b, r[3][5], 8, 5);
    mix!(b, r[3][6], 10, 3);
    mix!(b, r[3][7], 12, 7);
}

/// Inverts [`mix4`]. Constant time.
#[inline(always)]
fn unmix4(b: &mut [u64; 16], r: &[[u32; 8]; 4]) {
    unmix!(b, r[3][0], 0, 15);
    unmix!(b, r[3][1], 2, 11);
    unmix!(b, r[3][2], 6, 13);
    unmix!(b, r[3][3], 4, 9);
    unmix!(b, r[3][4], 14, 1);
    unmix!(b, r[3][5], 8, 5);
    unmix!(b, r[3][6], 10, 3);
    unmix!(b, r[3][7], 12, 7);

    unmix!(b, r[2][0], 0, 7);
    unmix!(b, r[2][1], 2, 5);
    unmix!(b, r[2][2], 4, 3);
    unmix!(b, r[2][3], 6, 1);
    unmix!(b, r[2][4], 12, 15);
    unmix!(b, r[2][5], 14, 13);
    unmix!(b, r[2][6], 8, 11);
    unmix!(b, r[2][7], 10, 9);

    unmix!(b, r[1][0], 0, 9);
    unmix!(b, r[1][1], 2, 13);
    unmix!(b, r[1][2], 6, 11);
    unmix!(b, r[1][3], 4, 15);
    unmix!(b, r[1][4], 10, 7);
    unmix!(b, r[1][5], 12, 3);
    unmix!(b, r[1][6], 14, 5);
    unmix!(b, r[1][7], 8, 1);

    unmix!(b, r[0][0], 0, 1);
    unmix!(b, r[0][1], 2, 3);
    unmix!(b, r[0][2], 4, 5);
    unmix!(b, r[0][3], 6, 7);
    unmix!(b, r[0][4], 8, 9);
    unmix!(b, r[0][5], 10, 11);
    unmix!(b, r[0][6], 12, 13);
    unmix!(b, r[0][7], 14, 15);
}

/// Encrypts one block in place. Constant time: rotations, pairs and schedule
/// offsets follow the public round number.
pub(crate) fn encrypt(kw: &[u64], t: &[u64; 5], block: &mut [u64]) {
    let (kw, b) = fixed::<16, 33>(kw, block);
    inject(b, kw, t, 0, 0, 0);
    for d in (1..ROUNDS / 4).step_by(2) {
        let (dm17, dm3) = (d % 17, d % 3);
        mix4(b, &R[0]);
        inject(b, kw, t, dm17, dm3, d);
        mix4(b, &R[1]);
        inject(b, kw, t, dm17 + 1, dm3 + 1, d + 1);
    }
}

/// Decrypts one block in place. Constant time: rotations, pairs and schedule
/// offsets follow the public round number.
pub(crate) fn decrypt(kw: &[u64], t: &[u64; 5], block: &mut [u64]) {
    let (kw, b) = fixed::<16, 33>(kw, block);
    for d in (1..ROUNDS / 4).step_by(2).rev() {
        let (dm17, dm3) = (d % 17, d % 3);
        eject(b, kw, t, dm17 + 1, dm3 + 1, d + 1);
        unmix4(b, &R[1]);
        eject(b, kw, t, dm17, dm3, d);
        unmix4(b, &R[0]);
    }
    eject(b, kw, t, 0, 0, 0);
}
