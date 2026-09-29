use crate::{BlockCipherPadding, PaddingError};
use core::fmt::{Display, Formatter};

/// ANSI X9.23 padding: zeros followed by the padding count.
///
/// Removal checks only the count byte; the filler carries no redundancy, so
/// corruption inside it goes unnoticed. Blocks must be shorter than 256 bytes.
/// The type is stateless, so one value can pad any number of blocks.
///
/// Constant time with respect to the block contents; `pad_count` reveals
/// through its result whether the count was in range.
///
/// # Example
///
/// ```
/// use tc_block_padding::{BlockCipherPadding, PaddingError, X923Padding};
///
/// let mut padding = X923Padding::new();
/// let mut block = *b"hello\xff\xff\xff";
/// assert_eq!(padding.add_padding(&mut block, 5)?, 3);
/// assert_eq!(block, *b"hello\x00\x00\x03");
/// assert_eq!(padding.pad_count(&block)?, 3);
///
/// // Only the count is checked, not the filler.
/// assert_eq!(padding.pad_count(b"hello\xaa\xbb\x03")?, 3);
/// # Ok::<(), PaddingError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X923Padding;

impl X923Padding {
    /// Creates an X9.23 padding. Constant time.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for X923Padding {
    type Error = PaddingError;

    /// Zero-fills `block[position..]` and writes the padding count into the
    /// last byte of the block.
    ///
    /// Constant time with respect to the block contents.
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

        filler.fill(0x00);
        *last = count as u8;
        Ok(count)
    }

    /// Reads the padding count from the last byte of the block.
    ///
    /// The check is the branch-free range test Bouncy Castle uses, so it runs
    /// in constant time with respect to the block contents. Only the count is
    /// verified: X9.23 filler is arbitrary and carries no redundancy, so
    /// corruption inside it is undetectable. The result reveals whether the
    /// count was in range; see the crate documentation on padding oracles.
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

impl Display for X923Padding {
    /// Writes `X9.23`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("X9.23")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::X923Padding;
    use crate::{BlockCipherPadding, PaddingError};

    #[test]
    fn zero_fills_and_records_the_count_in_the_last_byte() {
        let mut padding = X923Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0xff, 0xff, 0xff, 0, 0, 0, 0, 5]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn a_single_padding_byte_is_only_the_count() {
        let mut padding = X923Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 7), Ok(1));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]);
        assert_eq!(padding.pad_count(&block), Ok(1));
    }

    #[test]
    fn an_empty_block_pads_to_its_full_length() {
        let mut padding = X923Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [0, 0, 0, 0, 0, 0, 0, 8]);
        assert_eq!(padding.pad_count(&block), Ok(8));
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = X923Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = X923Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_blocks_too_long_for_a_single_byte_count() {
        let mut padding = X923Padding::new();
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
        let padding = X923Padding::new();

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
    fn filler_corruption_is_undetectable() {
        let padding = X923Padding::new();

        // Only the count byte is verified and the filler is arbitrary, so this is
        // still a valid X9.23 block.
        assert_eq!(padding.pad_count(&[1, 2, 0xaa, 0xbb, 3]), Ok(3));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        let mut padding = X923Padding::new();

        for used in 0..8 {
            let mut block = [0xa5_u8; 8];
            let added = padding.add_padding(&mut block, used).unwrap();

            assert_eq!(added, 8 - used);
            assert_eq!(padding.pad_count(&block), Ok(8 - used));
        }
    }

    #[test]
    fn reports_its_algorithm_name() {
        assert_eq!(X923Padding::new().to_string(), "X9.23");
    }
}
