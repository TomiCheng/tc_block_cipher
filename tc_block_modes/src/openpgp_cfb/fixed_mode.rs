//! Allocation-free OpenPGP CFB mode.

use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;

/// Allocation-free OpenPGP CFB over an `N`-byte block cipher, the variant of
/// RFC 4880 section 13.9 that resynchronizes after the first block and two
/// bytes.
///
/// The first block is full-block CFB. The second block encrypts its first two
/// bytes, then shifts those ciphertext bytes into the register before the
/// rest; every later block continues full-block CFB from there. The caller
/// supplies OpenPGP's prefix of one random block plus two repeated bytes as
/// the start of the data, as Bouncy Castle's `OpenPgpCfbBlockCipher`
/// expects; the mode neither creates nor checks it. The engine is always
/// initialized for encryption. The IV may be at most `N` bytes: a shorter one
/// is right-aligned over zeros, so an empty one is all zeros, which is what
/// OpenPGP uses.
///
/// Initialization rejects an engine whose block size is not `N`, and a block
/// shorter than two bytes. The state is stored inline and wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs and
/// copies, and branches only on the public block count.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{FixedOpenPgpCfbBlockCipher, KeyWithIvRef};
///
/// // OpenPGP encrypts its random prefix and the message under an all-zero IV.
/// let key = [0x42; 16];
/// let params = KeyWithIvRef::new(&key, &[]);
/// let message = *b"a random block, two check bytes and the message!";
///
/// let mut mode = FixedOpenPgpCfbBlockCipher::<_, 16>::new(AesEngine::new());
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 48];
/// for (block, out) in message.chunks_exact(16).zip(ciphertext.chunks_exact_mut(16)) {
///     mode.process_block(block, out)?;
/// }
///
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 48];
/// for (block, out) in ciphertext.chunks_exact(16).zip(recovered.chunks_exact_mut(16)) {
///     mode.process_block(block, out)?;
/// }
/// assert_eq!(recovered, message);
/// assert_eq!(mode.to_string(), "AES/OpenPGPCFB");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedOpenPgpCfbBlockCipher<C, const N: usize> {
    cipher: C,
    iv: [u8; N],
    register: [u8; N],
    keystream: [u8; N],
    count: usize,
    direction: CipherDirection,
    initialised: bool,
}

impl<C, const N: usize> FixedOpenPgpCfbBlockCipher<C, N> {
    /// Wraps `cipher` without allocating. Constant time: nothing is inspected.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            register: [0; N],
            keystream: [0; N],
            count: 0,
            direction: CipherDirection::Encrypt,
            initialised: false,
        }
    }
}

impl<C, const N: usize> Drop for FixedOpenPgpCfbBlockCipher<C, N> {
    /// Wipes the IV and the chaining or keystream state; the engine wipes
    /// its own key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.register.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: Display, const N: usize> Display for FixedOpenPgpCfbBlockCipher<C, N> {
    /// Writes the engine's name followed by `/OpenPGPCFB`.
    /// Constant time with respect to the key when the engine's `Display` is;
    /// output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/OpenPGPCFB")
    }
}

impl<C: BlockCipher, const N: usize> BlockCipher for FixedOpenPgpCfbBlockCipher<C, N> {
    type Error = BlockModeError<C::Error>;

    /// Returns `N`. Constant time.
    fn block_size(&self) -> usize {
        N
    }

    /// Encrypts or decrypts the first `N` bytes and returns `N`.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than `N`, leaving the
    /// register unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        if input.len() < N || output.len() < N {
            return Err(BlockModeError::BufferTooShort);
        }

        super::process_block(
            &mut self.cipher,
            self.direction,
            &mut self.register,
            &mut self.keystream,
            &mut self.count,
            &input[..N],
            &mut output[..N],
        )
        .map_err(BlockModeError::Cipher)?;
        Ok(N)
    }
}

impl<C, P, const N: usize> BlockCipherInit<P> for FixedOpenPgpCfbBlockCipher<C, N>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the block size and IV, initializes the engine for encryption,
    /// then installs the IV and the direction and restarts the register.
    ///
    /// Returns `UnsupportedBlockSize` for an engine whose block is not `N` or
    /// is shorter than two bytes, `InvalidIvLength` for an IV longer than `N`,
    /// or the engine's error; each leaves the previous IV, direction and
    /// register in place. Constant time exactly when the engine's `init` is:
    /// the mode only checks public lengths and copies the IV.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }
        if N < 2 {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual: N,
                required: 2,
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
        self.direction = direction;
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher, const N: usize> BlockCipherMode for FixedOpenPgpCfbBlockCipher<C, N> {
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
