//! Threefish-512 after Bouncy Castle's `Threefish512Cipher`.

use super::{eject, fixed, inject};

const ROUNDS: usize = 72;

/// Rotation constants from Skein 1.3, as two groups of four rounds.
#[rustfmt::skip]
const R: [[[u32; 4]; 4]; 2] = [
    [[46, 36, 19, 37], [33, 27, 14, 42], [17, 49, 36, 39], [44, 9, 54, 56]],
    [[39, 30, 34, 24], [13, 50, 10, 17], [25, 29, 39, 43], [8, 35, 56, 22]],
];

/// Four rounds with the word permutation folded into the pairs. Constant time.
#[inline(always)]
fn mix4(b: &mut [u64; 8], r: &[[u32; 4]; 4]) {
    mix!(b, r[0][0], 0, 1);
    mix!(b, r[0][1], 2, 3);
    mix!(b, r[0][2], 4, 5);
    mix!(b, r[0][3], 6, 7);

    mix!(b, r[1][0], 2, 1);
    mix!(b, r[1][1], 4, 7);
    mix!(b, r[1][2], 6, 5);
    mix!(b, r[1][3], 0, 3);

    mix!(b, r[2][0], 4, 1);
    mix!(b, r[2][1], 6, 3);
    mix!(b, r[2][2], 0, 5);
    mix!(b, r[2][3], 2, 7);

    mix!(b, r[3][0], 6, 1);
    mix!(b, r[3][1], 0, 7);
    mix!(b, r[3][2], 2, 5);
    mix!(b, r[3][3], 4, 3);
}

/// Inverts [`mix4`]. Constant time.
#[inline(always)]
fn unmix4(b: &mut [u64; 8], r: &[[u32; 4]; 4]) {
    unmix!(b, r[3][0], 6, 1);
    unmix!(b, r[3][1], 0, 7);
    unmix!(b, r[3][2], 2, 5);
    unmix!(b, r[3][3], 4, 3);

    unmix!(b, r[2][0], 4, 1);
    unmix!(b, r[2][1], 6, 3);
    unmix!(b, r[2][2], 0, 5);
    unmix!(b, r[2][3], 2, 7);

    unmix!(b, r[1][0], 2, 1);
    unmix!(b, r[1][1], 4, 7);
    unmix!(b, r[1][2], 6, 5);
    unmix!(b, r[1][3], 0, 3);

    unmix!(b, r[0][0], 0, 1);
    unmix!(b, r[0][1], 2, 3);
    unmix!(b, r[0][2], 4, 5);
    unmix!(b, r[0][3], 6, 7);
}

/// Encrypts one block in place. Constant time: rotations, pairs and schedule
/// offsets follow the public round number.
pub(crate) fn encrypt(kw: &[u64], t: &[u64; 5], block: &mut [u64]) {
    let (kw, b) = fixed::<8, 17>(kw, block);
    inject(b, kw, t, 0, 0, 0);
    for d in (1..ROUNDS / 4).step_by(2) {
        let (dm9, dm3) = (d % 9, d % 3);
        mix4(b, &R[0]);
        inject(b, kw, t, dm9, dm3, d);
        mix4(b, &R[1]);
        inject(b, kw, t, dm9 + 1, dm3 + 1, d + 1);
    }
}

/// Decrypts one block in place. Constant time: rotations, pairs and schedule
/// offsets follow the public round number.
pub(crate) fn decrypt(kw: &[u64], t: &[u64; 5], block: &mut [u64]) {
    let (kw, b) = fixed::<8, 17>(kw, block);
    for d in (1..ROUNDS / 4).step_by(2).rev() {
        let (dm9, dm3) = (d % 9, d % 3);
        eject(b, kw, t, dm9 + 1, dm3 + 1, d + 1);
        unmix4(b, &R[1]);
        eject(b, kw, t, dm9, dm3, d);
        unmix4(b, &R[0]);
    }
    eject(b, kw, t, 0, 0, 0);
}
