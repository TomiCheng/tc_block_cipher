# tc_aria benchmarks

## Results

Measured on 2026-09-24 on a local `x86_64-pc-windows-msvc` host, using Rust
1.98.0, Cargo's optimized bench profile and all features. These results
describe this host and run, not a cross-platform ranking.

Each of the 24 cases used Criterion with a 3-second warm-up, a 15-second
measurement window and 100 samples. Values below are Criterion's estimates
from one local run, not portable performance guarantees.

### Single block

**MiB/s for 16-byte blocks; higher is better.**

| Key size | Table encrypt | RustCrypto encrypt | Table decrypt | RustCrypto decrypt |
| --- | ---: | ---: | ---: | ---: |
| 128-bit | 54.36 | 70.09 | 66.71 | 94.86 |
| 192-bit | 44.64 | 58.04 | 55.18 | 78.10 |
| 256-bit | 37.18 | 63.44 | 50.73 | 68.05 |

### Key setup

**Nanoseconds per `init`; lower is better.**

| Key size | Table encrypt | RustCrypto encrypt | Table decrypt | RustCrypto decrypt |
| --- | ---: | ---: | ---: | ---: |
| 128-bit | 231.65 | 397.29 | 377.75 | 311.64 |
| 192-bit | 271.57 | 372.24 | 414.23 | 346.89 |
| 256-bit | 284.18 | 395.39 | 436.45 | 404.37 |

### Reading the results

RustCrypto had higher block throughput at every key size in this run. The
table engine had faster encryption key setup, while RustCrypto had faster
decryption key setup. Both engines are variable time; these benchmarks do not
verify constant-time behaviour.

The suite measures key setup and single-block encryption and decryption
directly on each engine, not through `AriaEngine`. Setup reinitialises an
existing engine, including replacement of its previous schedule; construction
and final drop are excluded. Block timings exclude key setup and report
throughput for single 16-byte blocks, not multi-block parallelism.

Several cases showed noticeable variation and outliers; for example,
RustCrypto's 256-bit encryption measured faster than its 192-bit encryption.
Repeat measurements under controlled conditions before drawing conclusions
about small differences or scaling across key sizes.

## Running the benchmarks

Run the full suite, which takes roughly 7 to 8 minutes plus compilation and
analysis:

```powershell
cargo bench -p tc_aria --bench aria --all-features --locked
```

Reproduce only the single-block comparison:

```powershell
cargo bench -p tc_aria --bench aria --all-features --locked -- '^aria/(encrypt|decrypt)/'
```

Without `--all-features` only the 12 table cases run. For a smoke test without
performance measurement:

```powershell
cargo bench -p tc_aria --bench aria --all-features --locked -- --test
```
