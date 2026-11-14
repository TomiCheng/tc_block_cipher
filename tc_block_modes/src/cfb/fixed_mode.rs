//! Allocation-free standard CFB mode.

#[cfg(feature = "alloc")]
use crate::ParamsWithIvOwned;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams, ParamsWithIvRef};
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;

/// Allocation-free Cipher Feedback mode with an `N`-byte cipher block and an
/// `S`-byte segment.
///
/// Each segment is XORed with the leading bytes of the encrypted feedback
/// register, and the ciphertext segment is shifted into the register. `S = 1`
/// gives CFB8, which handles any message length; `S = N` gives full-block
/// CFB. The engine is always initialized for encryption. The IV may be at most
/// `N` bytes: a shorter one is right-aligned over zeros, so an empty one is
/// all zeros. Use a fresh, unpredictable IV for every message.
///
/// Initialization rejects an engine whose block size is not `N` and a segment
/// size outside `1..=N`. The state is stored inline and wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs and
/// copies.
///
/// # Example
///
/// CFB8 transforms a message of any length one byte at a time:
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{FixedCfbBlockCipher, KeyWithIvRef};
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let message = b"any length";
///
/// let mut mode = FixedCfbBlockCipher::<_, 16, 1>::new(AesEngine::new());
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 10];
/// for (byte, out) in message.chunks(1).zip(ciphertext.chunks_mut(1)) {
///     mode.process_block(byte, out)?;
/// }
///
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 10];
/// for (byte, out) in ciphertext.chunks(1).zip(recovered.chunks_mut(1)) {
///     mode.process_block(byte, out)?;
/// }
/// assert_eq!(&recovered, message);
/// assert_eq!(mode.to_string(), "AES/CFB8");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedCfbBlockCipher<C, const N: usize, const S: usize> {
    cipher: C,
    iv: [u8; N],
    register: [u8; N],
    keystream: [u8; N],
    direction: Option<CipherDirection>,
}

impl<C, const N: usize, const S: usize> FixedCfbBlockCipher<C, N, S> {
    /// Wraps `cipher` without allocating. Constant time: nothing is inspected.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            register: [0; N],
            keystream: [0; N],
            direction: None,
        }
    }
}

impl<C, const N: usize, const S: usize> Drop for FixedCfbBlockCipher<C, N, S> {
    /// Wipes the IV and the chaining or keystream state; the engine wipes
    /// its own key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.register.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: Display, const N: usize, const S: usize> Display for FixedCfbBlockCipher<C, N, S> {
    /// Writes the engine's name followed by `/CFB` and the segment size in
    /// bits. Constant time with respect to the key when the engine's `Display`
    /// is; output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        write!(f, "/CFB{}", S * 8)
    }
}

impl<C: BlockCipher, const N: usize, const S: usize> BlockCipher for FixedCfbBlockCipher<C, N, S> {
    type Error = BlockModeError<C::Error>;

    /// Returns the segment size `S`. Constant time.
    fn block_size(&self) -> usize {
        S
    }

    /// Encrypts or decrypts the first `S` bytes and returns `S`.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than `S`, leaving the
    /// register unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
        if input.len() < S || output.len() < S {
            return Err(BlockModeError::BufferTooShort);
        }

        self.cipher
            .process_block(&self.register, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        for ((output, input), keystream) in output[..S].iter_mut().zip(input).zip(&self.keystream) {
            *output = input ^ keystream;
        }

        let ciphertext = match direction {
            CipherDirection::Encrypt => &output[..S],
            CipherDirection::Decrypt => &input[..S],
        };
        self.register.copy_within(S.., 0);
        self.register[N - S..].copy_from_slice(ciphertext);
        Ok(S)
    }
}

impl<C: BlockCipher, const N: usize, const S: usize> FixedCfbBlockCipher<C, N, S> {
    // The body of both inits: the mode checks and keeps `iv` and has `init_cipher` initialize
    // the engine with what the engine takes
    fn init_with_iv<E>(
        &mut self,
        direction: CipherDirection,
        iv: &[u8],
        init_cipher: impl FnOnce(&mut C, CipherDirection) -> Result<(), E>,
    ) -> Result<(), BlockModeInitError<E>> {
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }
        if S == 0 || S > N {
            return Err(BlockModeInitError::InvalidFeedbackSize(S * 8));
        }
        if iv.len() > N {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        init_cipher(&mut self.cipher, CipherDirection::Encrypt)
            .map_err(BlockModeInitError::Cipher)?;

        // Right-align a short IV over zeros (FIPS 81), so an empty IV is all zeros.
        let offset = N - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.direction = Some(direction);
        self.reset();
        Ok(())
    }
}

impl<C, P, const N: usize, const S: usize> BlockCipherInit<P> for FixedCfbBlockCipher<C, N, S>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the sizes and IV, initializes the engine for encryption, then
    /// installs the IV and restarts the register.
    ///
    /// Returns `UnsupportedBlockSize` for an engine whose block is not `N`,
    /// `InvalidFeedbackSize` for a segment outside `1..=N`, `InvalidIvLength`
    /// for an IV longer than `N`, or the engine's error; each leaves the
    /// previous IV and register in place. Constant time exactly when the
    /// engine's `init` is: the mode only checks public lengths and copies the
    /// IV.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        self.init_with_iv(direction, params.iv(), |cipher, direction| {
            cipher.init(direction, params)
        })
    }
}

#[cfg(feature = "alloc")]
/// As the implementation over [`IvParams`], but the mode keeps the IV and
/// gives the engine only the inner parameters, as Bouncy Castle's
/// `ParametersWithIV`, so an engine with parameters of its own works here.
impl<C, TParams, const N: usize, const S: usize> BlockCipherInit<ParamsWithIvOwned<TParams>>
    for FixedCfbBlockCipher<C, N, S>
where
    C: BlockCipher + BlockCipherInit<TParams>,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<TParams>>::Error>;

    /// Checks and keeps `params.iv()` as the implementation over
    /// [`IvParams`] does, and initializes the engine with `params.params()`.
    /// Constant time exactly when the engine's `init` is.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &ParamsWithIvOwned<TParams>,
    ) -> Result<(), <Self as BlockCipherInit<ParamsWithIvOwned<TParams>>>::Error> {
        self.init_with_iv(direction, params.iv(), |cipher, direction| {
            cipher.init(direction, params.params())
        })
    }
}

/// As the implementation for `ParamsWithIvOwned`, over borrowed values and
/// without an allocator.
impl<'a, C, TParams, const N: usize, const S: usize> BlockCipherInit<ParamsWithIvRef<'a, TParams>>
    for FixedCfbBlockCipher<C, N, S>
where
    C: BlockCipher + BlockCipherInit<TParams>,
    TParams: ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<TParams>>::Error>;

    /// Checks and keeps `params.iv()` as the implementation over
    /// [`IvParams`] does, and initializes the engine with `params.params()`.
    /// Constant time exactly when the engine's `init` is.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &ParamsWithIvRef<'a, TParams>,
    ) -> Result<(), <Self as BlockCipherInit<ParamsWithIvRef<'a, TParams>>>::Error> {
        self.init_with_iv(direction, params.iv(), |cipher, direction| {
            cipher.init(direction, params.params())
        })
    }
}

impl<C: BlockCipher, const N: usize, const S: usize> BlockCipherMode
    for FixedCfbBlockCipher<C, N, S>
{
    type Cipher = C;

    /// Returns the wrapped engine. Constant time.
    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    /// Returns `true`: a final partial segment can be processed through a
    /// segment-sized buffer. Constant time.
    fn is_partial_block_okay(&self) -> bool {
        true
    }

    /// Restarts the register from the IV installed by the last `init`.
    /// Constant time.
    fn reset(&mut self) {
        self.register.copy_from_slice(&self.iv);
        self.keystream.fill(0);
    }
}
