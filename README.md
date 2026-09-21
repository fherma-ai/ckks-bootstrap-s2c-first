# CKKS bootstrapping, S2C-first — reference implementation

A submission to `ckks-bootstrapping/s2c@1.0.0` on FHERMA: one call to Poulpy's S2C-first CKKS bootstrapping (`SlotsToCoeffs → ModUp → CoeffsToSlots → EvalMod`) on one ciphertext, timed. Poulpy 0.8.3, toolchain
`nightly-2026-05-14`.

This repository is the reference implementation: the answer every
submission is compared to, and the harness every submission is measured in.

## Attribution

[Poulpy](https://github.com/poulpy-fhe/poulpy) is an open-source homomorphic
encryption library developed by the Poulpy project ([poulpy.dev](https://www.poulpy.dev/))
and released under the Apache License 2.0. The bootstrapping, its parameter
set and its implementation are Poulpy's. This repository calls Poulpy through
its public API in order to measure it on [FHERMA](https://www.fherma.io); it
claims no authorship of the library or of the algorithm, and FHERMA is not
affiliated with the Poulpy project.

## What the stage does

| | |
|---|---|
| Input | the message (`N/2` points on the unit disc from `case_seed`) encoded and encrypted at the preset's input layout: 160 bits, scale 2³⁵ |
| Operation | `ckks_bootstrap` on the preset `n16_d35_k720_p19_s2c`: SlotsToCoeffs, ModUp under sparse-secret encapsulation, CoeffsToSlots, EvalMod |
| Output | one ciphertext at 720 bits, scale 2³⁵, the same message with 19+ bits of precision |
| Measured on the platform | about 3.5 s (Intel Xeon 6776P, 24 cores, AVX-512 IFMA + Rayon). The four stages are specifications of their own — `slots-to-coeffs`, `mod-up`, `coeffs-to-slots`, `eval-mod` — on the same keys and inputs |

## What to change to make it faster

Three files are yours; everything else is the specification's and is laid
over your repository at every measurement, so a change to it is not measured.

| File | Role |
|---|---|
| `src/run.rs` | the bootstrap into the output buffer. **The only thing timed.** Replace its body with your own algorithm; the output must be the same bytes. |
| `src/init.rs` | your setup over the point and the keys — buffers, plans, keys onto a GPU. Never sees a case. Not timed. |
| `src/free.rs` | your teardown. Not timed. |
| `Cargo.toml` | the Poulpy backend, one cargo feature: `ref`, `avx`, `avx512`, `ifma`, `neon`, each with a `-rayon` variant. The reference builds `ifma-rayon`. |
| `config.jsonc` | `threads` for a `-rayon` backend; `0` is every core. |

`src/envelope/` (key generation from the seed, the case from its seed, the
canonical bytes, the precision check) and the generated `src/main.rs`,
`src/fherma.rs` are the specification's. Correctness is the sha256 of the
output: it must equal the reference's for the same point and seed, with no
tolerance. Precision is reported beside the time, not judged.

## Build, run, submit

```sh
cargo build --release                                                  # the platform's image: x86-64, AVX-512 IFMA
cargo build --release --no-default-features --features neon-rayon      # on an Apple M-series
./target/release/fherma-solution make point --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1,2
./target/release/fherma-solution point && cat point/out/results.json
```

The keys alone are about 18 GB: plan for 32 GB and one process at a time. A digest made on another backend or operating system will not equal
the platform's; the platform judges on its own machines.

To submit: `fherma implementation init ckks-bootstrapping/s2c@1.0.0` writes this
layout for you; push your repository and register the commit on the
platform. See the [documentation](https://www.fherma.io/docs/solution-kinds).
