//! Threefish round functions after Bouncy Castle's `ThreefishEngine`.
//!
//! Each block width has its own functions, unrolled to eight rounds per loop
//! iteration so the rotation amounts and the word permutation are constants.
//! The key schedule is not expanded in advance: the key words are kept as
//! `key || parity || key` and the tweak as `t0, t1, t0 ^ t1, t0, t1`, so each
//! subkey word is read at an offset without wrapping around.

/// Adds `b[y]` into `b[x]`, then rotates `b[y]` and XORs in the sum.
macro_rules! mix {
    ($b:ident, $rotation:expr, $x:literal, $y:literal) => {
        $b[$x] = $b[$x].wrapping_add($b[$y]);
        $b[$y] = $b[$y].rotate_left($rotation) ^ $b[$x];
    };
}

/// Inverts [`mix!`] on the same pair.
macro_rules! unmix {
    ($b:ident, $rotation:expr, $x:literal, $y:literal) => {
        $b[$y] = ($b[$y] ^ $b[$x]).rotate_right($rotation);
        $b[$x] = $b[$x].wrapping_sub($b[$y]);
    };
}

pub(crate) mod threefish1024;
pub(crate) mod threefish256;
pub(crate) mod threefish512;

/// Key-schedule parity constant from Skein 1.3.
pub(crate) const C_240: u64 = 0x1bd1_1bda_a9fc_1a22;

/// Checks a public block-width parameter. Constant time with respect to secrets.
pub(crate) const fn valid_word_count(words: usize) -> bool {
    matches!(words, 4 | 8 | 16)
}

/// Adds the subkey that starts at key word `k` and tweak word `s`.
///
/// Constant time: the offsets and the counter are the public round number.
#[inline(always)]
fn inject<const W: usize, const KW: usize>(
    b: &mut [u64; W],
    kw: &[u64; KW],
    t: &[u64; 5],
    k: usize,
    s: usize,
    counter: usize,
) {
    for (i, word) in b.iter_mut().enumerate() {
        *word = word.wrapping_add(kw[k + i]);
    }
    b[W - 3] = b[W - 3].wrapping_add(t[s]);
    b[W - 2] = b[W - 2].wrapping_add(t[s + 1]);
    b[W - 1] = b[W - 1].wrapping_add(counter as u64);
}

/// Subtracts the subkey that [`inject`] adds for the same arguments.
///
/// Constant time: the offsets and the counter are the public round number.
#[inline(always)]
fn eject<const W: usize, const KW: usize>(
    b: &mut [u64; W],
    kw: &[u64; KW],
    t: &[u64; 5],
    k: usize,
    s: usize,
    counter: usize,
) {
    for (i, word) in b.iter_mut().enumerate() {
        *word = word.wrapping_sub(kw[k + i]);
    }
    b[W - 3] = b[W - 3].wrapping_sub(t[s]);
    b[W - 2] = b[W - 2].wrapping_sub(t[s + 1]);
    b[W - 1] = b[W - 1].wrapping_sub(counter as u64);
}

/// Borrows the schedule and block at their fixed lengths.
///
/// The engines pass a whole block and a `2 * W + 1`-word schedule, so neither
/// conversion can fail. Constant time: the lengths are public.
#[inline(always)]
fn fixed<'a, const W: usize, const KW: usize>(
    kw: &'a [u64],
    block: &'a mut [u64],
) -> (&'a [u64; KW], &'a mut [u64; W]) {
    (
        kw.try_into().expect("the schedule holds 2 * W + 1 words"),
        block.try_into().expect("the block holds W words"),
    )
}
