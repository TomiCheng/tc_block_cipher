mod cipher;
mod engine;

pub use engine::Rc6Engine;

/// RC6 block length in bytes.
pub const BLOCK_BYTES: usize = 16;
/// RC6 round count.
pub const ROUNDS: usize = 20;
/// Maximum accepted RC6 key length in bytes.
pub const MAX_KEY_BYTES: usize = 255;
/// Algorithm name written by the engine.
pub const ALGO_NAME: &str = "RC6";
