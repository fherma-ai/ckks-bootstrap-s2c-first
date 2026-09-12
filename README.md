# ckks-bootstrap-reference

Reference implementation of the `ckks-bootstrapping/s2c` specification:
Poulpy's S2C-first bootstrapping pipeline (`SlotsToCoeffs → ModUp →
CoeffsToSlots → EvalMod`, sparse-secret encapsulation, Han–Ki EvalMod), the
configuration published at https://www.poulpy.dev/benchmarks/. Poulpy 0.8.3,
public API only; the bootstrap is called, not copied.

It is also the harness every submission to the specification runs in. The
platform pins the harness files and lets an author change `run.rs`, the
backend feature and `config.jsonc`. The design note is
`design/bootstrapping-benchmark.md` in the platform repository.

## Specification and points

| | |
|---|---|
| specification | the circuit: pipeline `S2CFirst` and its techniques (`init::PIPELINE`) |
| benchmark point | `{N, log_delta, output_k, key_seed}` — the sizes, and the seed keygen is derived from |
| preset | Poulpy's name for (specification, point): `init::preset_for(point)` finds it in `presets::bootstrapping::all()` by pipeline and sizes. No preset → not a point of this specification |
| case | one platform seed: message, encryption mask and error are derived from it |

Today Poulpy ships one S2C-first preset, so one point: `N=65536, log_delta=35,
output_k=720` (`n16_d35_k720_p19_s2c`: 16 levels restored at scale 2³⁵, 19+
bits of precision).

## Files

| file | role | measured | owner |
|---|---|---|---|
| `src/init.rs` | `State::init(point)`: the preset for the point, module, compiled context, secret, bootstrapping keys. | no | platform, pinned |
| `src/generate.rs` | `generate(state, seed)`: the bundle's `generate` — one case from its seed (message, encryption); inside the solution because it needs the secret. | no | platform, pinned |
| `src/run.rs` | `run(state, input)`: the bootstrap. Reference body = Poulpy's `ckks_bootstrap`, two statements. | **yes — only this** | submission may replace |
| `src/digest.rs` | `bytes(ct)`: the output ciphertext as bytes; `sha256(ct)`. Correctness = equal bytes. | no | platform, pinned |
| `src/backend.rs` | which Poulpy backend `BE` is, by cargo feature. | — | submission picks a feature |
| `src/main.rs` | the wrapper: point directory in, `out/` and `results.json` out, timer around `run`. | — | platform, pinned |
| `config.jsonc` | `threads`. | — | submission |

Another primitive (c2s, rescale, keyswitch, paco) = new `init.rs` and
`generate.rs` (what `State`, the case and the output are) and a new reference
`run.rs`; `main.rs`, `digest.rs` and the bundle's `make`/`verify` stay.

## Contract with the platform

The same as every Poulpy solution's generated `main.rs`:

```
./fherma-solution <point directory>
```

| in the point directory | content |
|---|---|
| `manifest.json` | `{"N": 65536, "log_delta": 35, "output_k": 720, "key_seed": 0, "cases": 100}` — the point and the case count |
| `cases/000017/case_seed.bin` | one u64 little-endian: `seeds[17]` of the point. The whole input |
| `config.jsonc` | optional overlay of the solution's own |
| `out/000017/ct.bin` | written: the output ciphertext's bytes (14 680 129 bytes at this point) |
| `out/results.json` | written after every case: `point`, `preset`, `poulpy`, `backend`, `threads`, `init_s`, `max_rss_bytes`, one row per case (`seconds`, `case_seed`, `generate_s`, `digest`) |

Seeds: the point's `seeds` list is the case list, as for every point; the case
directory is the position in the list. `key_seed` is a parameter of the point,
like `N`.

Correctness: bundle `verify` = `sha256(out/NNNNNN/ct.bin)` against
`expected/NNNNNN/sha256`. Score: the row's `seconds`, one `run` per case; the
median over a point's cases is the platform's fold, as for every point. Three
discarded warm-up runs on the first case before anything is timed.

The reference run and a submission run are the same run; the platform keeps
the reference's digests as `expected/` and compares a submission's.

```
./fherma-solution make <dir> --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1,2,3
```

writes a point directory the way the bundle's `make` does, for local runs.

## Seeds → randomness

Every stream is `Source::new(sha256("fherma/ckks-bootstrap/" ‖ seed_le ‖ "/" ‖ stream))`:

| seed | streams |
|---|---|
| `key_seed` | `sk` (dense secret), `xs` (ephemeral sparse secret), `xe` (key error), `xa` (key mask) |
| case seed | `msg` (message), `input-xa`, `input-xe` |

The message is `N/2` points uniform on the unit disc: SplitMix64 over the
`msg` stream, uniform in the square, kept when inside the disc — only
multiplication and comparison, no libm, so it is the same f64 vector
bit-for-bit on any platform. Poulpy's own test helpers draw encryption
randomness from a global counter (call-order dependent); this crate does not
use them, so a case depends on its seed alone.

## Digest

sha256 over: `"fherma/ckks-ct/v1"`, then `n, cols, base2k, k, log_delta, slots`
as little-endian u64, then the limbs `0..size` of every column as little-endian
i64 (`size` = limbs carrying the current `k` bits). Independent of the buffer's
allocation and of what an earlier computation left beyond `k`.
`out/NNNNNN/ct.bin` is exactly these bytes.

## Build

Toolchain `nightly-2026-05-14` (Poulpy's pin; `rust-toolchain.toml`).

```
cargo build --release                                              # ref (portable baseline)
RUSTFLAGS="-C target-cpu=native" cargo build --release --no-default-features --features neon-rayon
RUSTFLAGS="-C target-cpu=native" cargo build --release --no-default-features --features ifma-rayon
```

One backend feature: `ref`, `neon`, `neon-rayon`, `avx`, `avx-rayon`,
`avx512`, `avx512-rayon`, `ifma`, `ifma-rayon`. `*-rayon` backends take
`threads` from `config.jsonc`. All are exact NTT backends (`init` asserts
`BE::DFT_IS_EXACT`); Poulpy's approximate FFT64 backends run the preset at
another radix and are not offered.

The `images/poulpy` image pins 0.8.2 and warms `poulpy-cpu-ref`/`-avx`/`-arm`;
building this offline needs 0.8.3, `poulpy-cpu-avx512` (`enable-avx512f`,
`enable-ifma`, `enable-rayon`), `rayon`, `sha2`, `libc` in the warm set.

## Run

```
./fherma-solution make point --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1,2,3
./fherma-solution point
cat point/out/results.json
shasum -a 256 point/out/000000/ct.bin      # equals the row's digest
```

## Numbers

Apple M-series (14 cores, 36 GB), one process at a time, ref backend
(`NTT4x30Ref`), point `N=65536 log_delta=35 output_k=720 key_seed=0`:

| | |
|---|---|
| init (keygen + compile) | 105–112 s |
| generate (one case) | 0.04–0.17 s |
| one bootstrap | 124–157 s |
| peak RSS | 16–23 GB single-thread, 26 GB with rayon × 4 (the peak depends on memory pressure; plan for 32 GB) |
| output per case | 14 680 129 bytes |

Poulpy's published numbers for the same preset (Ryzen 9 9950X): ref 1 thread
39.4 s, AVX-512/IFMA + Rayon 16 threads 2.29 s. Decrypting the output during
Phase 0 gave 22.42 bits of precision (Poulpy publishes 21.9 / 22.0); the
harness does not decrypt — correctness is the digest.

Reference digests at this point, ref backend (what `expected/` will hold):

| seed | sha256 of `ct.bin` |
|---|---|
| 1 | `1818321bef150bb32b70317b66651860f1c725a6bfca43dc3f1cdd235f4f18a1` |
| 2 | `2115944c2b905c3be05a3dd5fd3e47fa6e0325878f081c3056c25463f2c33cde` |
| 3 | `fd4f1da7ab7af4179551e1da67f8944168adcaedaa550ee61ea2eae6c8b0fa06` |

Memory is the runner requirement for this point: up to 26 GB resident per
process; `results.json` reports it as `max_rss_bytes`. Two such processes on a
36 GB machine do not fit.

Assumption the design rests on: Poulpy's output bytes are the same on every
exact backend and across Poulpy versions. Phase 0 found the DFT-matrix
encoding inside `BootstrappingContext::compile` differs between `NTT4x30Ref`
and `NTT4x30Neon` at the C2S scale (2⁴⁸); Poulpy is fixing it on their side.
Until then a digest is valid for the backend that produced it.
