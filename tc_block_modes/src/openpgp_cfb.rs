mod fixed_mode;
#[cfg(feature = "alloc")]
mod mode;

pub use fixed_mode::FixedOpenPgpCfbBlockCipher;
#[cfg(feature = "alloc")]
pub use mode::OpenPgpCfbBlockCipher;

use tc_block_cipher::{BlockCipher, CipherDirection};

/// Transforms one block of OpenPGP CFB, as Bouncy Castle's
/// `OpenPgpCfbBlockCipher` does.
///
/// The first block is plain full-block CFB. The second block encrypts its
/// first two bytes under the same register, then resynchronizes: the register
/// shifts by two and takes those two ciphertext bytes before the rest of the
/// block is processed. Every later block is full-block CFB offset by those two
/// bytes. `count` tracks how far the stream has come and stops growing after
/// the second block. Constant time exactly when the engine's `process_block`
/// is: the branches follow the public block count and direction.
fn process_block<C: BlockCipher>(
    cipher: &mut C,
    direction: CipherDirection,
    register: &mut [u8],
    keystream: &mut [u8],
    count: &mut usize,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), C::Error> {
    let n = register.len();
    if *count > n {
        register[n - 2] = feed(direction, keystream[n - 2], input[0], &mut output[0]);
        register[n - 1] = feed(direction, keystream[n - 1], input[1], &mut output[1]);
        cipher.process_block(register, keystream)?;
        for index in 2..n {
            register[index - 2] = feed(
                direction,
                keystream[index - 2],
                input[index],
                &mut output[index],
            );
        }
    } else if *count == 0 {
        cipher.process_block(register, keystream)?;
        for index in 0..n {
            register[index] = feed(
                direction,
                keystream[index],
                input[index],
                &mut output[index],
            );
        }
        *count += n;
    } else {
        cipher.process_block(register, keystream)?;
        let first = feed(direction, keystream[0], input[0], &mut output[0]);
        let second = feed(direction, keystream[1], input[1], &mut output[1]);
        register.copy_within(2.., 0);
        register[n - 2] = first;
        register[n - 1] = second;
        cipher.process_block(register, keystream)?;
        for index in 2..n {
            register[index - 2] = feed(
                direction,
                keystream[index - 2],
                input[index],
                &mut output[index],
            );
        }
        *count += n;
    }
    Ok(())
}

/// Writes `keystream ^ input` to `output` and returns the ciphertext byte the
/// register takes: the output when encrypting, the input when decrypting.
/// Constant time: the branch follows the public direction.
fn feed(direction: CipherDirection, keystream: u8, input: u8, output: &mut u8) -> u8 {
    *output = keystream ^ input;
    match direction {
        CipherDirection::Encrypt => *output,
        CipherDirection::Decrypt => input,
    }
}
