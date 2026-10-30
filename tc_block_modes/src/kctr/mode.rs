//! Runtime-sized KCTR mode.

use super::increment_le;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;

/// DSTU 7624 counter mode (KCTR) over the block cipher `C`, sized at runtime.
///
/// Available with the `alloc` feature. The engine first encrypts the IV to
/// seed the counter. Each block then increments the counter as a
/// little-endian integer, encrypts it and XORs the result into the data.
/// Encryption and decryption are the same operation, so the requested
/// direction is ignored and the engine is always initialized for encryption.
/// The IV may be at most one block: a shorter one is right-aligned over zeros,
/// so an empty one is all zeros. The IV must never repeat under one key: a
/// repeat reuses the keystream and reveals the XOR of the two plaintexts. The
/// state is wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs, copies
/// and a branch-free counter increment.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{KctrBlockCipher, KeyWithIvRef};
/// use tc_dstu7624::Dstu7624Engine256;
///
/// let (key, iv) = ([0x42; 32], [0x24; 32]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let mut mode = KctrBlockCipher::new(Dstu7624Engine256::new());
///
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 32];
/// mode.process_block(b"a single block of thirty-two by.", &mut ciphertext)?;
///
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 32];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"a single block of thirty-two by.");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct KctrBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    first_counter: Vec<u8>,
    counter: Vec<u8>,
    keystream: Vec<u8>,
    seeded: bool,
    initialised: bool,
}

impl<C: BlockCipher> KctrBlockCipher<C> {
    /// Wraps `cipher` and allocates four blocks of counter state.
    /// Constant time: only the engine's block size is read.
    pub fn new(cipher: C) -> Self {
        let block_size = cipher.block_size();
        Self {
            cipher,
            iv: vec![0; block_size],
            first_counter: vec![0; block_size],
            counter: vec![0; block_size],
            keystream: vec![0; block_size],
            seeded: false,
            initialised: false,
        }
    }
}

impl<C> Drop for KctrBlockCipher<C> {
    /// Wipes the IV, the counters and the keystream; the engine wipes its own
    /// key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.first_counter.zeroize();
        self.counter.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: Display> Display for KctrBlockCipher<C> {
    /// Writes the engine's name followed by `/KCTR`.
    /// Constant time with respect to the key when the engine's `Display` is;
    /// output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/KCTR")
    }
}

impl<C: BlockCipher> BlockCipher for KctrBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    /// Returns the engine's block size. Constant time.
    fn block_size(&self) -> usize {
        self.counter.len()
    }

    /// XORs the first block with the next keystream block, advances the
    /// counter and returns the block size. The first block after `init` or
    /// `reset` also encrypts the IV to seed the counter.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than a block, leaving the
    /// counter unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        let block_size = self.counter.len();
        if input.len() < block_size || output.len() < block_size {
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
        for ((output, input), keystream) in output[..block_size]
            .iter_mut()
            .zip(input)
            .zip(&self.keystream)
        {
            *output = input ^ keystream;
        }
        increment_le(&mut self.counter);
        Ok(block_size)
    }
}

impl<C, P> BlockCipherInit<P> for KctrBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the IV, initializes the engine for encryption, then installs the
    /// IV and restarts the counter. The direction is ignored.
    ///
    /// Returns `InvalidIvLength` for an IV longer than the block, or the
    /// engine's error; each leaves the previous IV and counter in place.
    /// Constant time exactly when the engine's `init` is: the mode only checks
    /// public lengths and copies the IV.
    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let block_size = self.cipher.block_size();
        let iv = params.iv();
        if iv.len() > block_size {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        // The engine's block size may have changed since new(); size the buffers from this init.
        self.iv.resize(block_size, 0);
        self.first_counter.resize(block_size, 0);
        self.counter.resize(block_size, 0);
        self.keystream.resize(block_size, 0);
        let offset = block_size - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.seeded = false;
        self.first_counter.fill(0);
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher> BlockCipherMode for KctrBlockCipher<C> {
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
