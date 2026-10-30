//! Allocation-free KCTR mode.

use super::increment_le;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;

/// Allocation-free DSTU 7624 counter mode (KCTR) over an `N`-byte block
/// cipher.
///
/// The engine first encrypts the IV to seed the counter. Each block then
/// increments the counter as a little-endian integer, encrypts it and XORs the
/// result into the data. Encryption and decryption are the same operation, so
/// the requested direction is ignored and the engine is always initialized for
/// encryption. The IV may be at most `N` bytes: a shorter one is right-aligned
/// over zeros, so an empty one is all zeros. The IV must never repeat under
/// one key: a repeat reuses the keystream and reveals the XOR of the two
/// plaintexts.
///
/// The mode is defined for DSTU 7624 (Kalyna) but accepts any engine whose
/// block is `N` bytes; initialization rejects any other block size. The state
/// is stored inline and wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs, copies
/// and a branch-free counter increment.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{FixedKctrBlockCipher, KeyWithIvRef};
/// use tc_dstu7624::Dstu7624Engine128;
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let mut mode = FixedKctrBlockCipher::<_, 16>::new(Dstu7624Engine128::new());
///
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 16];
/// mode.process_block(b"one single block", &mut ciphertext)?;
///
/// // Decryption applies the same keystream.
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 16];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"one single block");
/// assert_eq!(mode.to_string(), "DSTU7624/KCTR");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedKctrBlockCipher<C, const N: usize> {
    cipher: C,
    iv: [u8; N],
    first_counter: [u8; N],
    counter: [u8; N],
    keystream: [u8; N],
    seeded: bool,
    initialised: bool,
}

impl<C, const N: usize> FixedKctrBlockCipher<C, N> {
    /// Wraps `cipher` without allocating. Constant time: nothing is inspected.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            first_counter: [0; N],
            counter: [0; N],
            keystream: [0; N],
            seeded: false,
            initialised: false,
        }
    }
}

impl<C, const N: usize> Drop for FixedKctrBlockCipher<C, N> {
    /// Wipes the IV, the counters and the keystream; the engine wipes its own
    /// key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.first_counter.zeroize();
        self.counter.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: Display, const N: usize> Display for FixedKctrBlockCipher<C, N> {
    /// Writes the engine's name followed by `/KCTR`.
    /// Constant time with respect to the key when the engine's `Display` is;
    /// output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/KCTR")
    }
}

impl<C: BlockCipher, const N: usize> BlockCipher for FixedKctrBlockCipher<C, N> {
    type Error = BlockModeError<C::Error>;

    /// Returns `N`. Constant time.
    fn block_size(&self) -> usize {
        N
    }

    /// XORs the first `N` bytes with the next keystream block, advances the
    /// counter and returns `N`. The first block after `init` or `reset` also
    /// encrypts the IV to seed the counter.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than `N`, leaving the
    /// counter unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        if input.len() < N || output.len() < N {
            return Err(BlockModeError::BufferTooShort);
        }

        if !self.seeded {
            self.cipher
                .process_block(&self.iv, &mut self.first_counter)
                .map_err(BlockModeError::Cipher)?;
            increment_le(&mut self.first_counter);
            self.counter.copy_from_slice(&self.first_counter);
            self.seeded = true;
        }

        self.cipher
            .process_block(&self.counter, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        for ((output, input), keystream) in output[..N].iter_mut().zip(input).zip(&self.keystream) {
            *output = input ^ keystream;
        }
        increment_le(&mut self.counter);
        Ok(N)
    }
}

impl<C, P, const N: usize> BlockCipherInit<P> for FixedKctrBlockCipher<C, N>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the block size and IV, initializes the engine for encryption,
    /// then installs the IV and restarts the counter. The direction is
    /// ignored.
    ///
    /// Returns `UnsupportedBlockSize` for an engine whose block is not `N`,
    /// `InvalidIvLength` for an IV longer than `N`, or the engine's error;
    /// each leaves the previous IV and counter in place. Constant time exactly
    /// when the engine's `init` is: the mode only checks public lengths and
    /// copies the IV.
    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }

        let iv = params.iv();
        if iv.len() > N {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        let offset = N - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.seeded = false;
        self.first_counter.fill(0);
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher, const N: usize> BlockCipherMode for FixedKctrBlockCipher<C, N> {
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

    /// Restarts the counter from the value the IV seeded, or leaves it to be
    /// seeded by the next block. Constant time.
    fn reset(&mut self) {
        self.counter.copy_from_slice(&self.first_counter);
        self.keystream.fill(0);
    }
}
