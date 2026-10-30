//! Threefish key setup and single-block benchmarks for all available engines.
//!
//! Run `cargo bench -p tc_threefish --bench threefish`, or add `--all-features`
//! to include RustCrypto. Optional Criterion filters follow `--`, for example
//! `-- 'threefish/encrypt/portable/512'`.
//!
//! Setup benchmarks reinitialise an existing engine with a key and a tweak,
//! including replacement of its old state; construction and final drop are
//! outside the timing. Block benchmarks exclude key setup and report bytes per
//! second. The portable and RustCrypto engines are measured, not the
//! dispatcher. These are performance measurements, not constant-time
//! verification.

use std::{hint::black_box, time::Duration};

use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
#[cfg(feature = "rustcrypto")]
use tc_threefish::ThreefishRustCryptoEngine;
use tc_threefish::{ThreefishParamsRef, ThreefishPortableEngine};

fn add_engine<E, const WORDS: usize>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    direction: CipherDirection,
    setup: bool,
    create: impl Fn() -> E,
) where
    E: BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<ThreefishParamsRef<'a>, Error = InitError>,
{
    let size = WORDS * 8;
    let key: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(0x3d)).collect();
    let tweak: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x1b));
    let params = ThreefishParamsRef::with_tweak(&key, &tweak);
    let plaintext: Vec<u8> = (0..size).map(|i| i as u8).collect();

    let mut encryptor = create();
    encryptor.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = vec![0; size];
    encryptor
        .process_block(&plaintext, &mut ciphertext)
        .unwrap();
    let (input, expected) = match direction {
        CipherDirection::Encrypt => (plaintext, ciphertext),
        CipherDirection::Decrypt => (ciphertext, plaintext),
    };
    let mut engine = create();
    engine.init(direction, &params).unwrap();
    let mut output = vec![0; size];
    assert_eq!(engine.process_block(&input, &mut output), Ok(size));
    assert_eq!(output, expected);

    group.throughput(if setup {
        Throughput::Elements(1)
    } else {
        Throughput::Bytes(size as u64)
    });
    group.bench_function(BenchmarkId::new(name, size * 8), |b| {
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

fn add_width<const WORDS: usize>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    direction: CipherDirection,
    setup: bool,
) {
    add_engine::<_, WORDS>(
        group,
        "portable",
        direction,
        setup,
        ThreefishPortableEngine::<WORDS>::new,
    );
    #[cfg(feature = "rustcrypto")]
    add_engine::<_, WORDS>(
        group,
        "rustcrypto",
        direction,
        setup,
        ThreefishRustCryptoEngine::<WORDS>::new,
    );
}

fn benchmarks(c: &mut Criterion) {
    for (operation, direction, setup) in [
        ("init-encrypt", CipherDirection::Encrypt, true),
        ("init-decrypt", CipherDirection::Decrypt, true),
        ("encrypt", CipherDirection::Encrypt, false),
        ("decrypt", CipherDirection::Decrypt, false),
    ] {
        let mut group = c.benchmark_group(format!("threefish/{operation}"));
        add_width::<4>(&mut group, direction, setup);
        add_width::<8>(&mut group, direction, setup);
        add_width::<16>(&mut group, direction, setup);
        group.finish();
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
