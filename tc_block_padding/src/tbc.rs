use crate::{BlockCipherPadding, PaddingError};
use core::fmt::{Display, Formatter};

/// Trailing bit complement (TBC) padding.
///
/// The padding bytes are all `0xff` when the message's last bit is 0 and all
/// `0x00` when it is 1, so the padding always differs from the message's final
/// bit. Removal counts the trailing run of equal bytes and cannot detect
/// corruption. It works with any block length. The type is stateless, so one
/// value can pad any number of blocks.
///
/// Constant time with respect to the block contents.
///
/// # Example
///
/// ```
/// use tc_block_padding::{BlockCipherPadding, PaddingError, TbcPadding};
///
/// let mut padding = TbcPadding::new();
///
/// // 'o' (0x6f) ends in bit 1, so the padding is 0x00.
/// let mut block = *b"hello\xff\xff\xff";
/// assert_eq!(padding.add_padding(&mut block, 5)?, 3);
/// assert_eq!(block, *b"hello\x00\x00\x00");
/// assert_eq!(padding.pad_count(&block)?, 3);
///
/// // 'l' (0x6c) ends in bit 0, so the padding is 0xff.
/// let mut block = *b"hell\x00\x00\x00\x00";
/// padding.add_padding(&mut block, 4)?;
/// assert_eq!(block, *b"hell\xff\xff\xff\xff");
/// # Ok::<(), PaddingError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TbcPadding;

impl TbcPadding {
    /// Creates a trailing bit complement padding. Constant time.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for TbcPadding {
    type Error = PaddingError;

    /// Fills `block[position..]` with the complement of the message's last bit.
    ///
    /// When `position` is zero the whole block is padding and there is no
    /// message byte in it to look at. Bouncy Castle then reads the block's own
    /// last byte, which still holds whatever the caller left there, and this
    /// port keeps that behavior so both produce the same block.
    ///
    /// Constant time with respect to the block contents: the filler is derived
    /// from the message's last bit without branching on it.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is past the
    /// end of the block, and [`PaddingError::BlockFull`] when `position` equals
    /// the block length, since TBC must add at least one byte.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        let count = block
            .len()
            .checked_sub(position)
            .ok_or(PaddingError::PositionOutOfRange)?;
        if count == 0 {
            return Err(PaddingError::BlockFull);
        }

        // Take the message's last byte. When the whole block is padding there is none,
        // so, as Bouncy Castle does, fall back to the block's own last byte.
        let last = if position > 0 {
            block[position - 1]
        } else {
            block[block.len() - 1]
        };
        // A last bit of 0 wraps 0 - 1 to 0xff and a last bit of 1 gives 0x00, without
        // branching on plaintext.
        let code = (last & 0x01).wrapping_sub(1);

        block[position..].fill(code);
        Ok(count)
    }

    /// Counts the trailing run of bytes equals to the block's last byte.
    ///
    /// Bouncy Castle stops its loop as soon as the run ends. This port instead
    /// walks every byte with the same masked, branch-free scan used for
    /// zero-byte padding, so the count runs in constant time with respect to
    /// the block contents while producing the same result.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::CorruptPadding`] when the block is empty.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        let code = *block.last().ok_or(PaddingError::CorruptPadding)?;

        let mut count = 0;
        // still_run is only ever 0 or 1; 1 means every byte from the end up to here
        // equals code.
        let mut still_run = 1;

        for &byte in block.iter().rev() {
            // When equal, byte ^ code is 0 and subtracting 1 borrows to usize::MAX, which
            // shifts down to 1.
            let matches = ((byte ^ code) as usize).wrapping_sub(1) >> (usize::BITS - 1);
            still_run &= matches;
            count += still_run;
        }

        Ok(count)
    }
}

impl Display for TbcPadding {
    /// Writes `TBC`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("TBC")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::TbcPadding;
    use crate::{BlockCipherPadding, PaddingError};

    #[test]
    fn a_message_ending_in_a_zero_bit_is_padded_with_ones() {
        let mut padding = TbcPadding::new();
        let mut block = [0x11_u8; 8];
        block[2] = 0x1e; // last bit 0

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0x11, 0x11, 0x1e, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn a_message_ending_in_a_one_bit_is_padded_with_zeros() {
        let mut padding = TbcPadding::new();
        let mut block = [0x11_u8; 8];
        block[2] = 0x1f; // last bit 1

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0x11, 0x11, 0x1f, 0, 0, 0, 0, 0]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn the_run_never_reaches_into_the_message() {
        let mut padding = TbcPadding::new();

        // The message's last byte is 0xfe (last bit 0), so the padding is 0xff; the two
        // differ, so the count stops at the right place.
        let mut block = [0xfe_u8; 8];
        assert_eq!(padding.add_padding(&mut block, 4), Ok(4));
        assert_eq!(block, [0xfe, 0xfe, 0xfe, 0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(padding.pad_count(&block), Ok(4));
    }

    #[test]
    fn a_single_padding_byte_is_recovered() {
        let mut padding = TbcPadding::new();
        let mut block = [0x1f_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 7), Ok(1));
        assert_eq!(block, [0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0]);
        assert_eq!(padding.pad_count(&block), Ok(1));
    }

    #[test]
    fn a_whole_block_of_padding_uses_the_blocks_own_last_byte() {
        let mut padding = TbcPadding::new();

        // With position 0 there is no message byte to read, so, as Bouncy Castle does,
        // it reads the block's last byte 0x1e (last bit 0).
        let mut block = [0x1e_u8; 8];
        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [0xff; 8]);
        assert_eq!(padding.pad_count(&block), Ok(8));
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = TbcPadding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = TbcPadding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_an_empty_block() {
        let padding = TbcPadding::new();

        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        let mut padding = TbcPadding::new();

        for used in 1..8 {
            let mut block = [0xa5_u8; 8];
            let added = padding.add_padding(&mut block, used).unwrap();

            assert_eq!(added, 8 - used);
            assert_eq!(padding.pad_count(&block), Ok(8 - used));
        }
    }

    #[test]
    fn reports_its_algorithm_name() {
        assert_eq!(TbcPadding::new().to_string(), "TBC");
    }
}
