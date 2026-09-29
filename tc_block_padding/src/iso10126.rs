use crate::{BlockCipherPadding, PaddingError};
use core::fmt::{Display, Formatter};
use rand_core::CryptoRng;

/// ISO 10126-2 padding: random bytes followed by the padding count.
///
/// Available with the `rand_core` feature. The padding owns its generator
/// `R`, supplied at construction, because it draws from it on every call to
/// [`add_padding`](BlockCipherPadding::add_padding). Removal checks only the
/// count byte. Blocks must be shorter than 256 bytes. ISO 10126-2 is
/// withdrawn; use this scheme for compatibility, for example with XML
/// Encryption.
///
/// Constant time with respect to the block contents, apart from the
/// generator's own timing; `pad_count` reveals through its result whether the
/// count was in range.
///
/// # Example
///
/// ```
/// use tc_block_padding::{BlockCipherPadding, Iso10126Padding, PaddingError};
///
/// let mut padding = Iso10126Padding::new(rand::rng());
/// let mut block = *b"hello\0\0\0";
/// assert_eq!(padding.add_padding(&mut block, 5)?, 3);
/// assert_eq!(&block[..5], b"hello");
/// assert_eq!(block[7], 3); // bytes 5 and 6 are random
/// assert_eq!(padding.pad_count(&block)?, 3);
/// # Ok::<(), PaddingError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Iso10126Padding<R> {
    rng: R,
}

impl<R> Iso10126Padding<R> {
    /// Creates a padding that draws its filler from `rng`. Constant time.
    pub const fn new(rng: R) -> Self {
        Self { rng }
    }

    /// Consumes the padding and returns its generator. Constant time.
    pub fn into_inner(self) -> R {
        self.rng
    }
}

impl<R: CryptoRng> BlockCipherPadding for Iso10126Padding<R> {
    type Error = PaddingError;

    /// Fills `block[position..]` with random bytes and writes the padding count
    /// into the last byte of the block.
    ///
    /// Constant time with respect to the block contents; drawing the filler
    /// takes the generator's own time.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is past the
    /// end of the block, [`PaddingError::BlockFull`] when `position` equals the
    /// block length, since the count byte alone needs room, and
    /// [`PaddingError::UnsupportedBlockSize`] for blocks of 256 bytes or more.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let tail = block
            .get_mut(position..)
            .ok_or(PaddingError::PositionOutOfRange)?;
        let count = tail.len();
        // split_last_mut returns None for an empty tail, which is exactly the case
        // with no room for the count byte.
        let (last, filler) = tail.split_last_mut().ok_or(PaddingError::BlockFull)?;

        self.rng.fill_bytes(filler);
        *last = count as u8;
        Ok(count)
    }

    /// Reads the padding count from the last byte of the block.
    ///
    /// The check is the branch-free range test Bouncy Castle uses, so it runs
    /// in constant time with respect to the block contents. It does not use the
    /// generator. The result reveals whether the count was in range;
    /// see the crate documentation on padding oracles.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::UnsupportedBlockSize`] for blocks of 256 bytes or
    /// more, and [`PaddingError::CorruptPadding`] when the block is empty or
    /// when the recorded count is zero or longer than the block.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let count = *block.last().ok_or(PaddingError::CorruptPadding)? as isize;
        // A count of 0 makes count - 1 equal -1; a count longer than the block makes
        // position negative.
        let position = block.len() as isize - count;
        let failed = (position | (count - 1)) >> (isize::BITS - 1);

        if failed != 0 {
            return Err(PaddingError::CorruptPadding);
        }

        Ok(count as usize)
    }
}

impl<R> Display for Iso10126Padding<R> {
    /// Writes `ISO10126-2`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("ISO10126-2")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::convert::Infallible;
    use std::string::ToString;
    use std::vec::Vec;

    use rand_core::{TryCryptoRng, TryRng};

    use super::Iso10126Padding;
    use crate::{BlockCipherPadding, PaddingError};

    /// A test generator that supplies fixed bytes, so the padding output is
    /// predictable.
    struct FixedCryptoRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl FixedCryptoRng {
        fn new(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                offset: 0,
            }
        }

        fn take(&mut self, output: &mut [u8]) {
            let end = self.offset + output.len();
            assert!(end <= self.bytes.len(), "fixed RNG exhausted");
            output.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }
    }

    impl TryRng for FixedCryptoRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut output = [0_u8; 4];
            self.take(&mut output);
            Ok(u32::from_le_bytes(output))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut output = [0_u8; 8];
            self.take(&mut output);
            Ok(u64::from_le_bytes(output))
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            self.take(output);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedCryptoRng {}

    #[test]
    fn fills_with_random_bytes_and_records_the_count() {
        let mut padding = Iso10126Padding::new(FixedCryptoRng::new(&[0x11, 0x22, 0x33]));
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 4), Ok(4));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0x11, 0x22, 0x33, 4]);
        assert_eq!(padding.pad_count(&block), Ok(4));
    }

    #[test]
    fn a_single_padding_byte_draws_no_randomness() {
        // With one byte left it all goes to the count, and nothing is drawn from the
        // generator.
        let mut padding = Iso10126Padding::new(FixedCryptoRng::new(&[]));
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 7), Ok(1));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]);
    }

    #[test]
    fn into_inner_returns_the_generator_where_padding_left_it() {
        let mut padding = Iso10126Padding::new(FixedCryptoRng::new(&[0x11, 0x22, 0x33]));
        padding.add_padding(&mut [0_u8; 4], 2).unwrap();

        // Padding two bytes draws one random byte; the other holds the count.
        assert_eq!(padding.into_inner().offset, 1);
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = Iso10126Padding::new(FixedCryptoRng::new(&[]));

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = Iso10126Padding::new(FixedCryptoRng::new(&[]));

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_blocks_too_long_for_a_single_byte_count() {
        let mut padding = Iso10126Padding::new(FixedCryptoRng::new(&[]));
        let mut block = [0_u8; 256];

        assert_eq!(
            padding.add_padding(&mut block, 0),
            Err(PaddingError::UnsupportedBlockSize)
        );
        assert_eq!(
            padding.pad_count(&block),
            Err(PaddingError::UnsupportedBlockSize)
        );
    }

    #[test]
    fn rejects_an_out_of_range_count() {
        let padding = Iso10126Padding::new(FixedCryptoRng::new(&[]));

        assert_eq!(
            padding.pad_count(&[1, 2, 3, 0]),
            Err(PaddingError::CorruptPadding)
        );
        assert_eq!(
            padding.pad_count(&[1, 2, 3, 9]),
            Err(PaddingError::CorruptPadding)
        );
        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        for used in 0..8 {
            let mut padding = Iso10126Padding::new(FixedCryptoRng::new(&[0x5a; 8]));
            let mut block = [0xa5_u8; 8];
            let added = padding.add_padding(&mut block, used).unwrap();

            assert_eq!(added, 8 - used);
            assert_eq!(padding.pad_count(&block), Ok(8 - used));
        }
    }

    #[test]
    fn reports_its_algorithm_name() {
        assert_eq!(
            Iso10126Padding::new(FixedCryptoRng::new(&[])).to_string(),
            "ISO10126-2"
        );
    }

    #[test]
    fn a_real_generator_pads_every_message_length_and_varies_the_filler() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        // A fixed seed keeps the test reproducible while the filler still comes from
        // a real CSPRNG.
        let mut padding = Iso10126Padding::new(StdRng::seed_from_u64(0x10126));

        for used in 0..16 {
            let mut block = [0xa5_u8; 16];

            assert_eq!(padding.add_padding(&mut block, used), Ok(16 - used));
            assert_eq!(block[..used], [0xa5; 16][..used]);
            assert_eq!(usize::from(block[15]), 16 - used);
            assert_eq!(padding.pad_count(&block), Ok(16 - used));
        }

        // Two full-block paddings from one generator must differ; they match by
        // chance with probability 2^-120.
        let (mut first, mut second) = ([0_u8; 16], [0_u8; 16]);
        padding.add_padding(&mut first, 0).unwrap();
        padding.add_padding(&mut second, 0).unwrap();
        assert_ne!(first[..15], second[..15]);
    }
}
