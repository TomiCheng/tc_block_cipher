# tc_camellia benchmarks

## Results

Measured on 2026-10-22 on a local `x86_64-pc-windows-msvc` host, using Rust
1.98.0, Cargo's optimized bench profile and all features. These results
describe this host and run, not a cross-platform ranking.

Each of the 36 cases used Criterion with a 3-second warm-up, a 15-second
measurement window and 100 samples. Values below are Criterion's estimates
from one local run, not portable performance guarantees.

### Single block

**MiB/s for 16-byte blocks; higher is better.**

Encryption:

| Key size | Table | Light | RustCrypto |
| --- | ---: | ---: | ---: |
| 128-bit | 205.53 | 97.57 | 143.21 |
| 192-bit | 153.00 | 79.51 | 108.12 |
| 256-bit | 153.51 | 85.14 | 105.93 |

Decryption:

| Key size | Table | Light | RustCrypto |
| --- | ---: | ---: | ---: |
| 128-bit | 209.99 | 112.79 | 142.64 |
| 192-bit | 159.07 | 85.31 | 103.36 |
| 256-bit | 159.23 | 84.76 | 107.57 |

### Key setup

**Nanoseconds per `init`; lower is better.**

Encryption:

| Key size | Table | Light | RustCrypto |
| --- | ---: | ---: | ---: |
| 128-bit | 220.91 | 223.19 | 79.72 |
| 192-bit | 217.94 | 265.13 | 66.32 |
| 256-bit | 238.10 | 249.69 | 74.86 |

Decryption:

| Key size | Table | Light | RustCrypto |
| --- | ---: | ---: | ---: |
| 128-bit | 158.17 | 345.22 | 69.25 |
| 192-bit | 176.88 | 217.67 | 57.55 |
| 256-bit | 237.57 | 209.59 | 57.27 |

### Reading the results

The table engine had the highest block throughput at every key size in this
run, roughly 1.4 times RustCrypto's and 1.9 times the light engine's.
RustCrypto had the fastest key setup, about three times faster than either
portable engine. The 192- and 256-bit key sizes share the same round count,
so their block timings are close. All three engines are variable time; these
benchmarks do not verify constant-time behaviour.

The suite measures key setup and single-block encryption and decryption
directly on each engine, not through `CamelliaEngine`. Setup reinitialises an
existing engine, including replacement of its previous schedule; construction
and final drop are excluded. Block timings exclude key setup and report
throughput for single 16-byte blocks, not multi-block parallelism.

Several cases showed noticeable variation and outliers; for example, the light
engine's 128-bit decryption key setup measured slower than its 192- and
256-bit setups. Repeat measurements under controlled conditions before drawing
conclusions about small differences or scaling across key sizes.

## Running the benchmarks

Run the full suite, which takes roughly 11 minutes plus compilation and
analysis:

```powershell
cargo bench -p tc_camellia --bench camellia --all-features --locked
```

Reproduce only the single-block comparison:

```powershell
cargo bench -p tc_camellia --bench camellia --all-features --locked -- '^camellia/(encrypt|decrypt)/'
```

Without `--all-features` only the 24 table and light cases run. For a smoke
test without performance measurement:

```powershell
cargo bench -p tc_camellia --bench camellia --all-features --locked -- --test
```
