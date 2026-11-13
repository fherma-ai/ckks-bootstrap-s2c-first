# CKKS bootstrapping, S2C-first — reference implementation

A submission to `ckks-bootstrapping/s2c@3.0.0` on FHERMA: one S2C-first CKKS
bootstrapping (`SlotsToCoeffs → ModUp → CoeffsToSlots → EvalMod`) of one
ciphertext, timed. Poulpy 0.10.0, toolchain `nightly-2026-05-14`.

This repository is the reference implementation: the answer every
submission is compared to, and the harness every submission is measured in.
Earlier versions of the specification are at earlier commits: `s2c@2.0.0`
(Poulpy 0.9.0, preset `n16_d35_k720_p19_s2c`) at `d5be7ac`.

## Attribution

[Poulpy](https://github.com/poulpy-fhe/poulpy) is an open-source homomorphic
encryption library developed by the Poulpy project ([poulpy.dev](https://www.poulpy.dev/))
and released under the Apache License 2.0. The bootstrapping, its parameter
sets and its implementation are Poulpy's. This repository calls Poulpy through
its public API in order to measure it on [FHERMA](https://www.fherma.io); it
claims no authorship of the library or of the algorithm, and FHERMA is not
affiliated with the Poulpy project.

## The points

A point is `N`, `log_delta`, `output_k` and `key_seed`. The first three select
the Poulpy S2C-first preset with those sizes, with the keys of power-of-two
rotations, at the radix of the NTT4x30 arithmetic for a failure probability of
2⁻¹²⁸:

| `N` | `log_delta` | `output_k` | Preset | EvalMod ring | base2k |
|---|---|---|---|---|---|
| 65536 | 35 | 685 | `n16_d35_k685_p19_s2c_ffr_ci` | conjugate-invariant | 52 |
| 65536 | 35 | 733 | `n16_d35_k733_p20_s2c` | standard | 53 |

A point with no such preset is not a point of this specification.

## What the specification fixes, and what is yours

The specification's files are on the host and say nothing about where the
bootstrap runs. They are laid over your repository at every measurement, so
a change to them is not measured:

| File | Role |
|---|---|
| `src/envelope/keys.rs` | the preset for the point; the secret and the bootstrapping keys from `key_seed`, on the client (`NTT4x30Portable`) |
| `src/envelope/case.rs` | the case: N/2 points on the unit disc from `case_seed`, encrypted at the preset's input layout |
| `src/envelope/bytes.rs` | the canonical bytes of the output, which the digest is over |
| `src/envelope/check.rs` | the output's precision against the message |
| `src/envelope/mod.rs` | the four functions the loop calls; three warm-up runs |
| `src/main.rs`, `src/fherma.rs` | generated from the signature: the loop and the types |

The rest is yours:

| File | Role |
|---|---|
| `src/init.rs` | setup over the point and the keys, never a case. Not timed. The reference compiles the context on its backend, moves the keys there and prepares them, allocates the buffers, and on a GPU records one bootstrap. Also `fherma_h2d` and `fherma_d2h` |
| `src/run.rs` | **the only thing timed.** The reference bootstraps (or replays the recording) and waits for the device |
| `src/backend.rs` | which Poulpy backend, by cargo feature |
| `src/free.rs` | teardown. Not timed |
| `Cargo.toml` | the backend feature: `ref`, `avx`, `avx512`, `ifma`, `neon`, each with a `-rayon` variant; `cuda`; `wgpu` (Metal). The reference builds `ifma-rayon` |
| `config.jsonc` | `threads` for a `-rayon` backend; `0` is every core |

## What is measured

The loop calls, per case: `fherma_h2d` (the case's ciphertext from the host to
the buffer the bootstrap reads), `run`, `fherma_d2h` (the output back to the
host). Each has its own clock; the score is `run` alone. The other two are
reported as `h2d_s` and `d2h_s` beside it, with `generate_s`, `digest_s`,
`write_s` and `check_s`. On a CPU backend the transfers are a copy between two
host layouts.

Correctness is the sha256 of the output's canonical bytes: it must equal the
reference's for the same point and seed, with no tolerance. Every exact
NTT backend gives the same bytes at one radix; a NEON build and a Metal build
of this commit agree on both points. Precision is reported beside the time,
not judged.

| Point | NEON (M-series, every core) | Metal (replayed) |
|---|---|---|
| k685 | 1.16 s | 240 ms |
| k733 | 1.37 s | 370 ms |

## Build, run, submit

```sh
cargo build --release                                                  # the platform's image: x86-64, AVX-512 IFMA
cargo build --release --no-default-features --features cuda            # an NVIDIA GPU, CUDA toolkit on the machine
cargo build --release --no-default-features --features neon-rayon      # on an Apple M-series
cargo build --release --no-default-features --features wgpu            # the GPU of an Apple M-series, through Metal
./target/release/fherma-solution make point --point '{"N":65536,"log_delta":35,"output_k":685,"key_seed":0}' --seeds 1,2
./target/release/fherma-solution point && cat point/out/results.json
```

On an M-series Mac with 36 GB the NEON build peaks at 11–13 GB and the Metal
one at 5–7 GB, so one process at a time is enough.

To submit: `fherma implementation init ckks-bootstrapping/s2c@3.0.0` writes this
layout for you; push your repository and register the commit on the
platform. See the [documentation](https://www.fherma.io/docs/solution-kinds).
