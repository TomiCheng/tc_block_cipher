/// A block cipher padding scheme.
///
/// A scheme fills the end of a message's final block before encryption and,
/// after decryption, reports how many trailing bytes to remove. It works on
/// one block and never touches a cipher.
///
/// # Example
///
/// Generic code can pad and unpad with any scheme:
///
/// ```
/// use tc_block_padding::{BlockCipherPadding, Iso7816d4Padding, Pkcs7Padding};
///
/// fn round_trip<P: BlockCipherPadding>(padding: &mut P, message: &[u8]) -> Result<usize, P::Error> {
///     let mut block = [0u8; 16];
///     block[..message.len()].copy_from_slice(message);
///     padding.add_padding(&mut block, message.len())?;
///     Ok(block.len() - padding.pad_count(&block)?)
/// }
///
/// assert_eq!(round_trip(&mut Pkcs7Padding::new(), b"hello")?, 5);
/// assert_eq!(round_trip(&mut Iso7816d4Padding::new(), b"hello")?, 5);
/// # Ok::<(), tc_block_padding::PaddingError>(())
/// ```
pub trait BlockCipherPadding {
    /// The failure type returned by padding operations.
    type Error: core::error::Error;

    /// Pads `block[position..]` and returns the number of padding bytes added.
    ///
    /// `block` is one complete cipher block whose first `position` bytes hold
    /// the end of the message; the scheme overwrites every byte from
    /// `position` to the end of the block. A scheme that must add at least one
    /// byte returns an error when `position` equals the block length, so a
    /// message that fills its last block needs a whole extra block, padded
    /// from `position` 0. Zero-byte padding instead adds nothing and returns
    /// `Ok(0)`.
    ///
    /// The receiver is mutable because schemes that draw padding from a random
    /// generator advance that generator here.
    ///
    /// Constant time with respect to the block contents in every scheme of
    /// this crate; ISO 10126 adds the generator's own timing. Other
    /// implementations define their own timing.
    ///
    /// # Errors
    ///
    /// Returns an error when `position` is greater than the block length, and
    /// for the scheme-specific cases each scheme documents, such as a full
    /// block or a block too long for the scheme's count byte.
    fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error>;

    /// Returns the number of padding bytes at the end of `block`.
    ///
    /// The message occupies `block.len() - pad_count(block)` bytes. Callers
    /// must treat the result as untrusted length information until the message
    /// itself has been authenticated: acting on whether decrypted data carried
    /// valid padding is a padding oracle.
    ///
    /// Constant time with respect to the block contents in every scheme of
    /// this crate, apart from what the result reveals: the count, and whether
    /// the padding was valid. Other implementations define their own timing.
    ///
    /// # Errors
    ///
    /// Self-describing schemes return an error when the trailing bytes are not
    /// a valid encoding. Schemes that encode no length always succeed.
    fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::boxed::Box;

    use super::BlockCipherPadding;
    use crate::PaddingError;

    /// A minimal self-describing padding: fills the tail with one fixed byte and
    /// counts that byte back from the end.
    struct TestPadding {
        filler: u8,
    }

    impl BlockCipherPadding for TestPadding {
        type Error = PaddingError;

        fn add_padding(&mut self, block: &mut [u8], position: usize) -> Result<usize, Self::Error> {
            let tail = block
                .get_mut(position..)
                .ok_or(PaddingError::PositionOutOfRange)?;
            tail.fill(self.filler);
            Ok(tail.len())
        }

        fn pad_count(&self, block: &[u8]) -> Result<usize, Self::Error> {
            let count = block
                .iter()
                .rev()
                .take_while(|&&byte| byte == self.filler)
                .count();
            if count == 0 {
                return Err(PaddingError::CorruptPadding);
            }
            Ok(count)
        }
    }

    #[test]
    fn padding_supports_dynamic_dispatch() {
        let mut padding: Box<dyn BlockCipherPadding<Error = PaddingError>> =
            Box::new(TestPadding { filler: 0xa5 });
        let mut block = [0xff_u8; 8];

        assert_eq!(padding.add_padding(&mut block, 5), Ok(3));
        assert_eq!(block, [0xff, 0xff, 0xff, 0xff, 0xff, 0xa5, 0xa5, 0xa5]);
        assert_eq!(padding.pad_count(&block), Ok(3));
    }

    #[test]
    fn a_position_past_the_block_is_rejected() {
        let mut padding = TestPadding { filler: 0xa5 };

        assert_eq!(
            padding.add_padding(&mut [0_u8; 8], 9),
            Err(PaddingError::PositionOutOfRange)
        );
    }

    #[test]
    fn self_describing_schemes_can_report_corruption() {
        let padding = TestPadding { filler: 0xa5 };

        assert_eq!(
            padding.pad_count(&[1, 2, 3, 4]),
            Err(PaddingError::CorruptPadding)
        );
        assert_eq!(padding.pad_count(&[]), Err(PaddingError::CorruptPadding));
    }
}
