//! DES and Triple DES key setup and single-block benchmarks for the table and
//! RustCrypto engines.
//!
//! Run `cargo bench -p tc_des --bench des --all-features`; without the
//! `rustcrypto` feature only the table engines run. Optional Criterion filters
//! follow `--`, for example `-- 'des-ede/encrypt/table/192'`.
//!
//! Setup benchmarks reinitialise an existing engine, including replacement
//! of its old schedule; construction and final drop are outside the timing.
//! Block benchmarks exclude key setup and report bytes per second. The engines
//! are called directly, not through the `DesEngine` and `DesEdeEngine`
//! dispatchers. These are performance measurements, not constant-time
//! verification.

use std::{hint::black_box, time::Duration};

use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};
use tc_des::{BLOCK_BYTES, DES_EDE_KEY_BYTES, DES_KEY_BYTES, DesEdeTableEngine, DesTableEngine};
#[cfg(feature = "rustcrypto")]
use tc_des::{DesEdeRustCryptoEngine, DesRustCryptoEngine};

const OPERATIONS: [(&str, CipherDirection, bool); 4] = [
    ("init-encrypt", CipherDirection::Encrypt, true),
    ("init-decrypt", CipherDirection::Decrypt, true),
    ("encrypt", CipherDirection::Encrypt, false),
    ("decrypt", CipherDirection::Decrypt, false),
];

fn group<'a>(
    c: &'a mut Criterion,
    algorithm: &str,
    operation: &str,
    setup: bool,
) -> BenchmarkGroup<'a, WallTime> {
    let mut group = c.benchmark_group(format!("{algorithm}/{operation}"));
    if setup {
        group.throughput(Throughput::Elements(1));
    } else {
        group.throughput(Throughput::Bytes(BLOCK_BYTES as u64));
    }
    group
}

fn add_engine<E>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    key_lengths: &[usize],
    direction: CipherDirection,
    setup: bool,
    create: impl Fn() -> E,
) where
    E: BlockCipher<Error = BlockError> + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>,
{
    let plaintext = core::array::from_fn::<_, BLOCK_BYTES, _>(|i| i as u8);
    for &key_len in key_lengths {
        let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(0x3d)).collect();
        let params = KeyRef::new(&key);
        let mut encryptor = create();
        encryptor.init(CipherDirection::Encrypt, &params).unwrap();
        let mut ciphertext = [0; BLOCK_BYTES];
        encryptor
            .process_block(&plaintext, &mut ciphertext)
            .unwrap();
        let (input, expected) = match direction {
            CipherDirection::Encrypt => (plaintext, ciphertext),
            CipherDirection::Decrypt => (ciphertext, plaintext),
        };
        let mut engine = create();
        engine.init(direction, &params).unwrap();
        let mut output = [0; BLOCK_BYTES];
        assert_eq!(engine.process_block(&input, &mut output), Ok(BLOCK_BYTES));
        assert_eq!(output, expected);

        group.bench_function(BenchmarkId::new(name, key_len * 8), |b| {
            if setup {
                b.iter(|| {
                    engine
                        .init(black_box(direction), black_box(&params))
                        .unwrap();
                    black_box(&mut engine);
                });
            } else {
                b.iter(|| {
                    let written = engine
                        .process_block(black_box(&input), black_box(&mut output))
                        .unwrap();
                    black_box(written);
                    black_box(&output);
                });
            }
        });
    }
}

fn benchmarks(c: &mut Criterion) {
    for (operation, direction, setup) in OPERATIONS {
        let mut des = group(c, "des", operation, setup);
        add_engine(
            &mut des,
            "table",
            &DES_KEY_BYTES,
            direction,
            setup,
            DesTableEngine::new,
        );
        #[cfg(feature = "rustcrypto")]
        add_engine(
            &mut des,
            "rustcrypto",
            &DES_KEY_BYTES,
            direction,
            setup,
            DesRustCryptoEngine::new,
        );
        des.finish();

        let mut des_ede = group(c, "des-ede", operation, setup);
        add_engine(
            &mut des_ede,
            "table",
            &DES_EDE_KEY_BYTES,
            direction,
            setup,
            DesEdeTableEngine::new,
        );
        #[cfg(feature = "rustcrypto")]
        add_engine(
            &mut des_ede,
            "rustcrypto",
            &DES_EDE_KEY_BYTES,
            direction,
            setup,
            DesEdeRustCryptoEngine::new,
        );
        des_ede.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15));
    targets = benchmarks
}
criterion_main!(benches);
