//! GOST 28147 counter mode (GCTR).

use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;

/// The engine block size GCTR is defined for, in bytes.
const BLOCK_BYTES: usize = 8;

/// The constant added to the low counter word, modulo `2^32`.
const C2: u32 = 0x0101_0101;
/// The constant added to the high counter word, modulo `2^32 - 1`.
const C1: u32 = 0x0101_0104;

/// GOST 28147-89 counter mode (GCTR), called GOFB in Bouncy Castle, over a
/// 64-bit block cipher.
///
/// The engine first encrypts the IV to seed two 32-bit counter words. Each
/// block then advances them by fixed constants, encrypts the counter block and
/// XORs the result into the data. Encryption and decryption are the same
/// operation, so the requested direction is ignored and the engine is always
/// initialized for encryption. The IV may be at most 8 bytes: a shorter one is
/// right-aligned over zeros, so an empty one is all zeros. The IV must never
/// repeat under one key: a repeat reuses the keystream and reveals the XOR of
/// the two plaintexts.
///
/// The mode is defined for GOST 28147 but accepts any engine with an 8-byte
/// block; initialization rejects any other block size. The state is stored
/// inline and wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs, copies
/// and branch-free counter arithmetic.
///
/// # Example
///
/// A GOST 28147 engine needs its S-box with the key, so the parameters are a
/// type of your own that supplies the key, the S-box and the IV:
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};
/// use tc_block_modes::{GofbBlockCipher, IvParams};
/// use tc_gost28147::{Gost28147Engine, Gost28147Params, s_box};
///
/// struct GostKeyWithIv<'a> {
///     key: &'a [u8],
///     iv: &'a [u8],
/// }
///
/// impl KeyParams for GostKeyWithIv<'_> {
///     fn key(&self) -> &[u8] {
///         self.key
///     }
/// }
///
/// impl Gost28147Params for GostKeyWithIv<'_> {
///     fn s_box(&self) -> &[u8] {
///         &s_box::E_A
///     }
/// }
///
/// impl IvParams for GostKeyWithIv<'_> {
///     fn iv(&self) -> &[u8] {
///         self.iv
///     }
/// }
///
/// let params = GostKeyWithIv { key: &[0x42; 32], iv: &[0x24; 8] };
/// let mut mode = GofbBlockCipher::new(Gost28147Engine::new());
///
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 8];
/// mode.process_block(b"8 bytes!", &mut ciphertext)?;
///
/// // Decryption applies the same keystream.
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 8];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"8 bytes!");
/// assert_eq!(mode.to_string(), "Gost28147/GCTR");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct GofbBlockCipher<C> {
    cipher: C,
    iv: [u8; BLOCK_BYTES],
    register: [u8; BLOCK_BYTES],
    keystream: [u8; BLOCK_BYTES],
    n3: u32,
    n4: u32,
    first_step: bool,
    initialised: bool,
}

impl<C> GofbBlockCipher<C> {
    /// Wraps `cipher` without allocating. Constant time: nothing is inspected.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; BLOCK_BYTES],
            register: [0; BLOCK_BYTES],
            keystream: [0; BLOCK_BYTES],
            n3: 0,
            n4: 0,
            first_step: true,
            initialised: false,
        }
    }
}

impl<C> Drop for GofbBlockCipher<C> {
    /// Wipes the IV, the counter and the keystream; the engine wipes its own
    /// key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.register.zeroize();
        self.keystream.zeroize();
        self.n3.zeroize();
        self.n4.zeroize();
    }
}

impl<C: Display> Display for GofbBlockCipher<C> {
    /// Writes the engine's name followed by `/GCTR`. Constant time with
    /// respect to the key when the engine's `Display` is; output timing
    /// depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/GCTR")
    }
}

impl<C: BlockCipher> BlockCipher for GofbBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    /// Returns 8. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// XORs the first 8 bytes with the next keystream block and returns 8.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than 8 bytes, leaving
    /// the counter unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockModeError::BufferTooShort);
        }

        let (mut n3, mut n4) = (self.n3, self.n4);
        if self.first_step {
            self.cipher
                .process_block(&self.register, &mut self.keystream)
                .map_err(BlockModeError::Cipher)?;
            n3 = u32::from_le_bytes(self.keystream[..4].try_into().unwrap());
            n4 = u32::from_le_bytes(self.keystream[4..].try_into().unwrap());
        }

        n3 = n3.wrapping_add(C2);
        n4 = n4.wrapping_add(C1);
        // Bouncy Castle adds one when the signed sum lies in 1..C1, its
        // approximation of addition modulo 2^32 - 1.
        n4 = n4.wrapping_add(less_than(n4.wrapping_sub(1), C1 - 1));
        let mut register = [0; BLOCK_BYTES];
        register[..4].copy_from_slice(&n3.to_le_bytes());
        register[4..].copy_from_slice(&n4.to_le_bytes());

        self.cipher
            .process_block(&register, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        for ((output, input), keystream) in output[..BLOCK_BYTES]
            .iter_mut()
            .zip(input)
            .zip(&self.keystream)
        {
            *output = input ^ keystream;
        }

        self.register = register;
        register.zeroize();
        (self.n3, self.n4) = (n3, n4);
        self.first_step = false;
        Ok(BLOCK_BYTES)
    }
}

impl<C, P> BlockCipherInit<P> for GofbBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the block size and IV, initializes the engine for encryption,
    /// then installs the IV and restarts the counter. The direction is
    /// ignored.
    ///
    /// Returns `UnsupportedBlockSize` for an engine whose block is not 8
    /// bytes, `InvalidIvLength` for an IV longer than 8 bytes, or the engine's
    /// error; each leaves the previous IV and counter in place. Constant time
    /// exactly when the engine's `init` is: the mode only checks public
    /// lengths and copies the IV.
    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let actual = self.cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }

        let iv = params.iv();
        if iv.len() > BLOCK_BYTES {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        let offset = BLOCK_BYTES - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher> BlockCipherMode for GofbBlockCipher<C> {
    type Cipher = C;

    /// Returns the wrapped engine. Constant time.
    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    /// Returns `true`: a final partial block can be processed through a
    /// block-sized buffer. Constant time.
    fn is_partial_block_okay(&self) -> bool {
        true
    }

    /// Restarts the counter from the IV installed by the last `init`; the next
    /// block encrypts the IV again to reseed it. Constant time.
    fn reset(&mut self) {
        self.register.copy_from_slice(&self.iv);
        self.keystream.fill(0);
        self.n3 = 0;
        self.n4 = 0;
        self.first_step = true;
    }
}

/// Returns 1 when `a < b` and 0 otherwise. Constant time: no branch or
/// comparison instruction depends on the operands.
fn less_than(a: u32, b: u32) -> u32 {
    ((!a & b) | (!(a ^ b) & a.wrapping_sub(b))) >> 31
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn less_than_agrees_with_the_comparison_operator_at_the_edges() {
        let values = [0, 1, C1 - 2, C1 - 1, C1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
        for a in values {
            for b in values {
                assert_eq!(less_than(a, b), u32::from(a < b), "{a:#x} < {b:#x}");
            }
        }
    }

    #[test]
    fn the_counter_fix_up_matches_bouncy_castles_signed_test() {
        for n4 in [0, 1, C1 - 1, C1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let signed = n4 as i32;
            let expected = u32::from(signed < C1 as i32 && signed > 0);
            assert_eq!(less_than(n4.wrapping_sub(1), C1 - 1), expected, "{n4:#x}");
        }
    }
}
