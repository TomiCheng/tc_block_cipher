use crate::{BlockCipherPadding, PaddingError};
use core::fmt::{Display, Formatter};

/// PKCS#7 padding (RFC 5652), the common default.
///
/// Every padding byte holds the padding count, from 1 up to the block length,
/// and removal checks all of them. Blocks must be shorter than 256 bytes. The
/// type is stateless, so one value can pad any number of blocks.
///
/// Constant time with respect to the block contents; `pad_count` reveals
/// through its result whether the padding was valid.
///
/// # Example
///
/// ```
/// use tc_block_padding::{BlockCipherPadding, PaddingError, Pkcs7Padding};
///
/// let mut padding = Pkcs7Padding::new();
/// let mut block = *b"hello\0\0\0";
/// assert_eq!(padding.add_padding(&mut block, 5)?, 3);
/// assert_eq!(block, *b"hello\x03\x03\x03");
/// assert_eq!(padding.pad_count(&block)?, 3);
///
/// // A padding byte that disagrees with the count is rejected.
/// assert_eq!(
///     padding.pad_count(b"hello\x03\x02\x03"),
///     Err(PaddingError::CorruptPadding)
/// );
/// # Ok::<(), PaddingError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pkcs7Padding;

impl Pkcs7Padding {
    /// Creates a PKCS#7 padding. Constant time.
    pub const fn new() -> Self {
        Self
    }
}

impl BlockCipherPadding for Pkcs7Padding {
    type Error = PaddingError;

    /// Writes the padding count into every byte of `block[position..]`.
    ///
    /// Constant time with respect to the block contents.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::PositionOutOfRange`] when `position` is past the
    /// end of the block, [`PaddingError::BlockFull`] when `position` equals the
    /// block length, since PKCS#7 must add at least one byte, and
    /// [`PaddingError::UnsupportedBlockSize`] for blocks of 256 bytes or more.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let tail = block
            .get_mut(position..)
            .ok_or(PaddingError::PositionOutOfRange)?;
        let count = tail.len();
        if count == 0 {
            return Err(PaddingError::BlockFull);
        }

        tail.fill(count as u8);
        Ok(count)
    }

    /// Reads the padding count from the last byte and verifies every padding
    /// byte against it.
    ///
    /// The verification is the masked, branch-free comparison Bouncy Castle
    /// uses, so it runs in constant time with respect to the block contents:
    /// a rejected block reveals only that it was rejected, never how far the
    /// comparison got. That the result reveals validity at all is inherent;
    /// see the crate documentation on padding oracles.
    ///
    /// # Errors
    ///
    /// Returns [`PaddingError::UnsupportedBlockSize`] for blocks of 256 bytes or
    /// more, and [`PaddingError::CorruptPadding`] when the block is empty, when
    /// the recorded count is zero or longer than the block, or when any byte in
    /// the padding region disagrees with it.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
        if block.len() > u8::MAX as usize {
            return Err(PaddingError::UnsupportedBlockSize);
        }

        let last = *block.last().ok_or(PaddingError::CorruptPadding)?;
        let count = last as isize;
        // position is where the padding starts. A count of 0 makes count - 1 equal -1,
        // and a count longer than the block makes position negative; both set the top bit.
        let position = block.len() as isize - count;
        let mut failed = (position | (count - 1)) >> (isize::BITS - 1);

        for (index, &byte) in block.iter().enumerate() {
            // The mask is all ones where index >= position (compare) and zero elsewhere (skip).
            let in_padding = !((index as isize - position) >> (isize::BITS - 1));
            failed |= (byte ^ last) as isize & in_padding;
        }

        // Branch only on the aggregated result; the per-byte comparison never branches.
        if failed != 0 {
            return Err(PaddingError::CorruptPadding);
        }

        Ok(count as usize)
    }
}

impl Display for Pkcs7Padding {
    /// Writes `PKCS7`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("PKCS7")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::Pkcs7Padding;
    use crate::{BlockCipherPadding, PaddingError};

    #[test]
    fn writes_the_count_into_every_padding_byte() {
        let mut padding = Pkcs7Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 3), Ok(5));
        assert_eq!(block, [0xff, 0xff, 0xff, 5, 5, 5, 5, 5]);
        assert_eq!(padding.pad_count(&block), Ok(5));
    }

    #[test]
    fn an_empty_block_pads_to_its_full_length() {
        let mut padding = Pkcs7Padding::new();
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 0), Ok(8));
        assert_eq!(block, [8; 8]);
        assert_eq!(padding.pad_count(&block), Ok(8));
    }

    #[test]
    fn a_full_block_has_no_room_for_padding() {
        let mut padding = Pkcs7Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 8),
            Err(PaddingError::BlockFull)
        );
    }

    #[test]
    fn rejects_a_position_past_the_end_of_the_block() {
        let mut padding = Pkcs7Padding::new();

        assert_eq!(
            padding.add_padding(&mut [0xff_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn rejects_blocks_too_long_for_a_single_byte_count() {
        let mut padding = Pkcs7Padding::new();
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
    fn rejects_corrupt_padding() {
        let padding = Pkcs7Padding::new();

        // A count of 0.
        assert_eq!(
            padding.pad_count(&[1, 2, 3, 0]),
            Err(PaddingError::CorruptPadding)
        );
        // A count longer than the block.
        assert_eq!(
            padding.pad_count(&[1, 2, 3, 9]),
            Err(PaddingError::CorruptPadding)
        );
        // A byte in the padding region disagrees with the count.
        assert_eq!(
            padding.pad_count(&[1, 3, 2, 3]),
            Err(PaddingError::CorruptPadding)
        );
        // An empty block.
        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }

    #[test]
    fn padding_round_trips_for_every_message_length() {
        let mut padding = Pkcs7Padding::new();

        for used in 0..8 {
            let mut block = [0xa5_u8; 8];
            let added = padding.add_padding(&mut block, used).unwrap();

            assert_eq!(added, 8 - used);
            assert_eq!(padding.pad_count(&block), Ok(8 - used));
        }
    }

    #[test]
    fn reports_its_algorithm_name() {
        assert_eq!(Pkcs7Padding::new().to_string(), "PKCS7");
    }
}
