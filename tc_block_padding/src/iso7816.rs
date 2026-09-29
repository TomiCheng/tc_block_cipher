use crate::{BlockCipherPadding, PaddingError};
use core::fmt::{Display, Formatter};

/// ISO 7816-4 padding: a `0x80` marker followed by zeros.
///
/// Also known as bit padding, and used by smart cards and several MACs. It
/// works with any block length. The type is stateless, so one value can pad
/// any number of blocks.
///
/// Constant time with respect to the block contents; `pad_count` reveals
/// through its result where the marker sat and whether one was found.
///
/// # Example
///
/// ```
/// use tc_block_padding::{BlockCipherPadding, Iso7816d4Padding, PaddingError};
///
/// let mut padding = Iso7816d4Padding::new();
/// let mut block = *b"hello\xff\xff\xff";
/// assert_eq!(padding.add_padding(&mut block, 5)?, 3);
/// assert_eq!(block, *b"hello\x80\x00\x00");
/// assert_eq!(padding.pad_count(&block)?, 3);
///
/// // A block with no marker is rejected.
/// assert_eq!(padding.pad_count(&[0; 8]), Err(PaddingError::CorruptPadding));
/// # Ok::<(), PaddingError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Iso7816d4Padding;

impl Iso7816d4Padding {
    /// Creates an ISO 7816-4 padding. Constant time.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for Iso7816d4Padding {
    type Error = PaddingError;

    /// Writes `0x80` at `position` and zeros to the end of the block.
    ///
    /// Constant time with respect to the block contents.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is past the
    /// end of the block, and [`PaddingError::BlockFull`] when `position` equals
    /// the block length, since the marker byte alone needs room.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        let tail = block
            .get_mut(position..)
            .ok_or(PaddingError::PositionOutOfRange)?;
        let count = tail.len();
        // split_first_mut returns None for an empty tail, which is exactly the case
        // with no room for 0x80.
        let (marker, rest) = tail.split_first_mut().ok_or(PaddingError::BlockFull)?;

        *marker = 0x80;
        rest.fill(0x00);
        Ok(count)
    }

    /// Locates the `0x80` marker and returns the number of bytes from it to the
    /// end of the block.
    ///
    /// The scan is the masked, branch-free walk Bouncy Castle uses: it always
    /// visits every byte, so it runs in constant time with respect to the block
    /// contents and its timing does not show where the marker sat. The result
    /// itself still reveals that position, through the count, and whether a
    /// marker was found; see the crate documentation on padding oracles.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::CorruptPadding`] when the block does not end in
    /// a `0x80` marker followed only by zeros.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        // position stays -1 until a valid marker is found; still_zero is all ones
        // while every byte from the end up to here has been 0x00.
        let mut position: isize = -1;
        let mut still_zero: isize = -1;

        for (index, &byte) in block.iter().enumerate().rev() {
            let value = byte as isize;
            // When the values are equal x ^ y is 0, and subtracting 1 borrows to -1,
            // whose top bit is 1; otherwise the result is 0.
            // For 0x00, value ^ 0x00 is value itself, so this writes value - 1 directly.
            let matches_00 = (value - 1) >> (isize::BITS - 1);
            let matches_80 = ((value ^ 0x80) - 1) >> (isize::BITS - 1);

            // Record the position only inside the trailing zeros and at a 0x80 byte.
            position ^= (index as isize ^ position) & still_zero & matches_80;
            still_zero &= matches_00;
        }

        // Branch only on the aggregated result; the per-byte scan never branches.
        if position < 0 {
            return Err(PaddingError::CorruptPadding);
        }

        Ok(block.len() - position as usize)
    }
}

impl Display for Iso7816d4Padding {
    /// Writes `ISO7816-4`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("ISO7816-4")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::Iso7816d4Padding;
    use crate::{BlockCipherPadding, PaddingError};

    #[test]
    fn writes_the_marker_then_zeros() {
        let mut padding = Iso7816d4Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn a_single_padding_byte_is_only_the_marker() {
        let mut padding = Iso7816d4Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 7), Ok(1));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80]);
        assert_eq!(padding.pad_count(&block), Ok(1));
    }

    #[test]
    fn an_empty_block_pads_to_its_full_length() {
        let mut padding = Iso7816d4Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(8));
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = Iso7816d4Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = Iso7816d4Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn stays_unambiguous_for_messages_ending_in_zero() {
        let mut padding = Iso7816d4Padding::new();
        let mut block = [0x00_u8; 8];
        block[0] = 0x01;

        // The message 01 00 00 itself ends in 0x00; the marker still lets it be
        // recovered.
        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0x01, 0, 0, 0x80, 0, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn takes_the_last_marker_when_the_message_contains_one() {
        let padding = Iso7816d4Padding::new();

        // A 0x80 inside the message does not count; only the one before the trailing
        // zeros does.
        assert_eq!(padding.pad_count(&[0x80, 0x01, 0x80, 0x00]), Ok(2));
    }

    #[test]
    fn rejects_a_block_without_a_marker() {
        let padding = Iso7816d4Padding::new();

        assert_eq!(
            padding.pad_count(&[1, 2, 3, 4]),
            Err(PaddingError::CorruptPadding)
        );
        // An all-zero block has no marker.
        assert_eq!(
            padding.pad_count(&[0, 0, 0, 0]),
            Err(PaddingError::CorruptPadding)
        );
        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        let mut padding = Iso7816d4Padding::new();

        for used in 0..8 {
            let mut block = [0xa5_u8; 8];
            let added = padding.add_padding(&mut block, used).unwrap();

            assert_eq!(added, 8 - used);
            assert_eq!(padding.pad_count(&block), Ok(8 - used));
        }
    }

    #[test]
    fn reports_its_algorithm_name() {
        assert_eq!(Iso7816d4Padding::new().to_string(), "ISO7816-4");
    }
}
