# tc_threefish benchmarks

## Results

Measured on 2026-10-30 on a local `x86_64-pc-windows-msvc` host, using Rust
1.98.0, Cargo's optimized bench profile and all features. These results
describe this host and run, not a cross-platform ranking.

Each of the 24 cases used Criterion with a 3-second warm-up, a 15-second
measurement window and 100 samples. Values below are Criterion's estimates
from one local run, not portable performance guarantees.

### Single block

**MiB/s for one block of the given width; higher is better.**

Encryption:

| Block size | Portable | RustCrypto |
| --- | ---: | ---: |
| 256-bit | 339.71 | 302.70 |
| 512-bit | 436.42 | 337.39 |
| 1024-bit | 466.95 | 242.19 |

Decryption:

| Block size | Portable | RustCrypto |
| --- | ---: | ---: |
| 256-bit | 403.60 | 267.86 |
| 512-bit | 467.52 | 288.92 |
| 1024-bit | 456.77 | 249.30 |

### Key setup

**Nanoseconds per `init` with a key and a tweak; lower is better.**

Encryption:

| Block size | Portable | RustCrypto |
| --- | ---: | ---: |
| 256-bit | 23.89 | 122.69 |
| 512-bit | 31.86 | 202.15 |
| 1024-bit | 59.19 | 599.72 |

Decryption:

| Block size | Portable | RustCrypto |
| --- | ---: | ---: |
| 256-bit | 19.70 | 125.64 |
| 512-bit | 32.70 | 174.27 |
| 1024-bit | 61.17 | 612.51 |

### Reading the results

The portable engine was faster in every case. Its key setup only stores the
key, its parity word and the tweak, and took a fifth to a tenth of the time of
RustCrypto's, which expands the whole subkey schedule. Its blocks were also
faster, from about 1.1 times for Threefish-256 encryption to about 1.9 times
for Threefish-1024, where RustCrypto's throughput fell below its 512-bit
figure. Both engines are constant time; these benchmarks do not verify
constant-time behaviour.

`ThreefishEngine` uses the RustCrypto engine when the `rustcrypto` feature is
enabled, so on this host enabling the feature makes it slower. Callers who
need speed should use `ThreefishPortableEngine` directly.

The suite measures key setup and single-block encryption and decryption
directly on each engine, not through `ThreefishEngine`. Setup reinitialises an
existing engine with a key and a tweak, including replacement of its previous
state; construction and final drop are excluded. Block timings exclude key
setup and report throughput for single blocks, not multi-block parallelism.

Several cases showed noticeable variation and outliers; up to 18 of 100
samples were outliers in one case, and a run made while the host was busy
measured some setup cases about 20 to 30 percent differently. Repeat
measurements under controlled conditions before drawing conclusions about
small differences, such as Threefish-256 encryption.

## Running the benchmarks

Run the full suite, which takes roughly 8 minutes plus compilation and
analysis:

```powershell
cargo bench -p tc_threefish --bench threefish --all-features --locked
```

Reproduce only the single-block comparison:

```powershell
cargo bench -p tc_threefish --bench threefish --all-features --locked -- '^threefish/(encrypt|decrypt)/'
```

Without `--all-features` only the 12 portable cases run. For a smoke test
without performance measurement:

```powershell
cargo bench -p tc_threefish --bench threefish --all-features --locked -- --test
```
