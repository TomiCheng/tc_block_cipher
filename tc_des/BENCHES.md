# tc_des benchmarks

## Results

Measured on 2026-09-24 on a local Windows x86-64 host with an 11th Gen Intel
Core i7-1185G7 at 3.00 GHz, using Rust 1.98.0 and Cargo's optimized bench
profile. These results describe this host and run, not a cross-platform
ranking.

Each of the 24 cases used Criterion with a 3-second warm-up, a 15-second
measurement window and 100 samples. Values below are Criterion's central time
estimates, rounded to one decimal place.

### Single block

**Nanoseconds per 8-byte block; lower is better. Each cell is encryption /
decryption.**

| Engine | DES | Triple DES, 16-byte key | Triple DES, 24-byte key |
| --- | ---: | ---: | ---: |
| `DesTableEngine` / `DesEdeTableEngine` | 86.4 / 98.2 | 267.8 / 267.0 | 275.9 / 268.1 |
| `DesRustCryptoEngine` / `DesEdeRustCryptoEngine` | 225.7 / 251.0 | 681.7 / 716.4 | 681.4 / 689.5 |

The table engines were about 2.6 times faster per block. Their SP-boxes fold the
P permutation into the S-box lookups, while the RustCrypto engines look up
smaller S-boxes and apply the permutations as separate bit operations. Triple
DES cost about three single-DES blocks with either key length, as expected
from its three passes.

### Key setup

**Nanoseconds per `init`; lower is better. Each cell is encryption /
decryption.**

| Engine | DES | Triple DES, 16-byte key | Triple DES, 24-byte key |
| --- | ---: | ---: | ---: |
| `DesTableEngine` / `DesEdeTableEngine` | 1171.9 / 1064.3 | 3272.0 / 3197.5 | 3784.0 / 3300.8 |
| `DesRustCryptoEngine` / `DesEdeRustCryptoEngine` | 129.4 / 124.5 | 264.2 / 259.9 | 381.2 / 381.2 |

The RustCrypto engines set up keys about 8.5 to 12 times faster. Their key
schedule uses fixed bit permutations, while the table engines build each
round key bit by bit and branch on key bits. The table engines expand the
first component of a 16-byte key twice, since `K1` also serves as `K3`; the
RustCrypto engine expands it once and reuses it.

### Reading the results

`DesEngine` and `DesEdeEngine` use the RustCrypto engines when the `rustcrypto`
feature is enabled because they leak less, not because they are faster: in
this run that choice made each block about 2.6 times slower and each key setup
8.5 to 12 times faster. Neither engine is constant time.

The measurements include each engine's `process_block` or `init` API overhead
but exclude construction and final drop. They call the engines directly, not
the dispatchers. Decryption uses ciphertext prepared before timing, and setup
benchmarks reinitialise an existing engine, including replacement of its
previous key schedule.

These are single-block measurements, not multi-block throughput or
constant-time verification. All but one case reported outliers, up to 16 of
100 samples; system load and CPU behaviour can affect small differences, and the
three-key Triple DES table setup had the widest confidence interval, 3.48 to
4.21 µs.

## Running the benchmarks

Run the full suite, which takes about 8 minutes on this host plus compilation
and analysis:

```powershell
cargo bench -p tc_des --bench des --all-features --locked
```

Reproduce only the single-block comparison:

```powershell
cargo bench -p tc_des --bench des --all-features --locked -- '^des(-ede)?/(encrypt|decrypt)/'
```

Without `--all-features` only the table engines run. For a smoke test without
performance measurement:

```powershell
cargo bench -p tc_des --bench des --all-features --locked -- --test
```
