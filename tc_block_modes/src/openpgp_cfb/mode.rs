//! Runtime-sized OpenPGP CFB mode.

use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;

/// OpenPGP CFB over the block cipher `C`, sized at runtime: the variant of
/// RFC 4880 section 13.9 that resynchronizes after the first block and two
/// bytes.
///
/// Available with the `alloc` feature. The first block is full-block CFB. The
/// second block encrypts its first two bytes, then shifts those ciphertext
/// bytes into the register before the rest; every later block continues
/// full-block CFB from there. The caller supplies OpenPGP's prefix of one
/// random block plus two repeated bytes as the start of the data, as Bouncy
/// Castle's `OpenPgpCfbBlockCipher` expects; the mode neither creates nor
/// checks it. The engine is always initialized for encryption. The IV may be
/// at most one block: a shorter one is right-aligned over zeros, so an empty
/// one is all zeros, which is what OpenPGP uses. The state is wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs and
/// copies, and branches only on the public block count.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{KeyWithIvRef, OpenPgpCfbBlockCipher};
///
/// let key = [0x42; 16];
/// let params = KeyWithIvRef::new(&key, &[]);
/// let mut mode = OpenPgpCfbBlockCipher::new(AesEngine::new());
///
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 16];
/// mode.process_block(b"one single block", &mut ciphertext)?;
///
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 16];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"one single block");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct OpenPgpCfbBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    register: Vec<u8>,
    keystream: Vec<u8>,
    count: usize,
    direction: CipherDirection,
    initialised: bool,
}

impl<C: BlockCipher> OpenPgpCfbBlockCipher<C> {
    /// Wraps `cipher` and allocates three blocks of chaining state.
    /// Constant time: only the engine's block size is read.
    pub fn new(cipher: C) -> Self {
        let block_size = cipher.block_size();
        Self {
            cipher,
            iv: vec![0; block_size],
            register: vec![0; block_size],
            keystream: vec![0; block_size],
            count: 0,
            direction: CipherDirection::Encrypt,
            initialised: false,
        }
    }
}

impl<C> Drop for OpenPgpCfbBlockCipher<C> {
    /// Wipes the IV and the chaining or keystream state; the engine wipes
    /// its own key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.register.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: Display> Display for OpenPgpCfbBlockCipher<C> {
    /// Writes the engine's name followed by `/OpenPGPCFB`.
    /// Constant time with respect to the key when the engine's `Display` is;
    /// output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/OpenPGPCFB")
    }
}

impl<C: BlockCipher> BlockCipher for OpenPgpCfbBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    /// Returns the engine's block size. Constant time.
    fn block_size(&self) -> usize {
        self.register.len()
    }

    /// Encrypts or decrypts the first block and returns the block size.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than a block, leaving the
    /// register unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        let block_size = self.register.len();
        if input.len() < block_size || output.len() < block_size {
            return Err(BlockModeError::BufferTooShort);
        }

        super::process_block(
            &mut self.cipher,
            self.direction,
            &mut self.register,
            &mut self.keystream,
            &mut self.count,
            &input[..block_size],
            &mut output[..block_size],
        )
        .map_err(BlockModeError::Cipher)?;
        Ok(block_size)
    }
}

impl<C, P> BlockCipherInit<P> for OpenPgpCfbBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the block size and IV, initializes the engine for encryption,
    /// then installs the IV and the direction and restarts the register.
    ///
    /// Returns `UnsupportedBlockSize` for an engine whose block is shorter
    /// than two bytes, `InvalidIvLength` for an IV longer than the block, or
    /// the engine's error; each leaves the previous IV, direction and register
    /// in place. Constant time exactly when the engine's `init` is: the mode
    /// only checks public lengths and copies the IV.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let block_size = self.cipher.block_size();
        if block_size < 2 {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual: block_size,
                required: 2,
            });
        }

        let iv = params.iv();
        if iv.len() > block_size {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        // The engine's block size may have changed since new(); size the buffers from this init.
        self.iv.resize(block_size, 0);
        self.register.resize(block_size, 0);
        self.keystream.resize(block_size, 0);
        let offset = block_size - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.direction = direction;
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher> BlockCipherMode for OpenPgpCfbBlockCipher<C> {
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

    /// Restarts from the IV installed by the last `init`, so the next block is
    /// a first block again. Constant time.
    fn reset(&mut self) {
        self.register.copy_from_slice(&self.iv);
        self.keystream.fill(0);
        self.count = 0;
    }
}
