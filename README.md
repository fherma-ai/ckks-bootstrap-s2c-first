# CKKS bootstrapping, S2C-first — a submission

A submission to the specification `ckks-bootstrapping/s2c@1.0.0`: one call to
Poulpy's S2C-first bootstrapping (`SlotsToCoeffs → ModUp → CoeffsToSlots →
EvalMod`) on one ciphertext, timed. Poulpy 0.8.3, toolchain
`nightly-2026-05-14`.

This directory is the reference implementation, and the harness the platform
measures every submission in: `fherma.toml [harness]` says which files are
the specification's (pinned — laid over every submission's clone) and which
are the author's. The reference is the harness with `src/init.rs`, `run.rs`
and `free.rs` as they ship, built on the fastest backend Poulpy has
(`ifma-rayon`, every core). A submission that keeps them competes on backend
and threads; one that replaces `run.rs` competes on the algorithm and must
produce the same bytes.

## The contract

| | |
|---|---|
| Input | the case's message — `N/2` points on the unit disc from `case_seed` — encoded and encrypted at the preset's input layout: 160 bits, scale 2³⁵. Made by `generate`, not measured |
| Operation | `ckks_bootstrap` on the preset's compiled context and prepared keys: SlotsToCoeffs, ModUp with sparse-secret encapsulation, CoeffsToSlots, EvalMod |
| Output | one ciphertext at 720 bits, scale 2³⁵, the same message with 19+ bits of precision |

The stages are specifications of their own — `slots-to-coeffs`, `mod-up`,
`coeffs-to-slots`, `eval-mod` — and the composition test beside their
references chains them through their own code and gets this bootstrap byte
for byte.

## Files

Three functions are yours; the envelope and the loop are the platform's:

| File | Owner | Role |
|---|---|---|
| `src/init.rs` | **you** | `init(&Point, &Context, config) → State`: your setup over the point and the context — the output buffers, a working arena, keys onto a GPU. Never sees a case. Not measured |
| `src/run.rs` | **you** | `run(&mut State, &Input) → &Output` — the bootstrap into the output buffer. **The only thing timed** |
| `src/free.rs` | **you** | `free(State)`: your teardown. Not measured |
| `Cargo.toml` | **you** | the backend, as one cargo feature under `[features] default` |
| `config.jsonc` | **you** | `threads`, for a `*-rayon` backend; `0` is every core |
| `rust-toolchain.toml` | you | `nightly-2026-05-14`; Poulpy needs nightly |
| `src/envelope/mod.rs` | specification, pinned | the envelope: `setup` (keygen from `key_seed`), `generate` (the case: the message encrypted), `serialize` (the output as canonical bytes), `check` (shape, and precision against the message); `WARMUP` |
| `src/envelope/{keys,case,bytes,check,backend}.rs` | specification, pinned | the envelope's parts; `backend.rs` picks the Poulpy backend from the cargo feature |
| `src/fherma.rs` | generated, pinned | the types, from the signature: `Point {N, log_delta, output_k, key_seed}`, `Inputs {case_seed}`, `Outputs {ct}` |
| `src/main.rs` | generated, pinned | the loop: `setup → init → [generate → warm-up → run → serialize → check]* → free`; point directory in, `out/` and `results.json` out, the clock around `run`. `fherma-lang emit --solution --envelope <signature>` |

## What is measured

One call to `run` per case, wall-clock seconds, after three discarded warm-up
calls on the first case. Every other stage is timed and reported beside it,
and none of them is the score:

| In `out/results.json` | Seconds spent |
|---|---|
| `setup_s` | the envelope's keygen and compiled bootstrapping context, once |
| `init_s` | your `init`, once |
| `warmup_s` | the three warm-up calls, once |
| per case `generate_s` | the case from its seed: encode and encrypt |
| per case `seconds` | **the score**: one `run` |
| per case `digest_s`, `write_s` | serialising the output and writing it |
| per case `check_s` | decrypting it for its precision |
| per case `metrics.precision_bits`, `precision_bits_avg`, `precision_bits_re`, `precision_bits_im`, `max_abs_err` | the worst slot and the average, as −log₂ of the absolute error against the message — Poulpy's own `precision_stats` |
| per case `valid` | the output has the shape a bootstrap leaves: the input's ring, slots and sparsity, back at scale 2³⁵, at least `output_k` bits wide |
| `config` | your `config.jsonc`, as the run saw it |
| `max_rss_bytes` | the process's peak resident memory, bytes |

## How correctness is judged

By digest against the reference. The output ciphertext is serialised
canonically — `"fherma/ckks-ct/v1"`, then `n, cols, base2k, k, log_delta,
slots` as little-endian u64, then the limbs carrying the current `k` bits of
every column as little-endian i64 — and written as `out/NNNNNN/ct.bin`. The
platform takes its sha256 and compares it with the one the reference
produced for the same point and seed. Equal is a pass; there is no tolerance.

## The point and the case

| | |
|---|---|
| Point | `{N, log_delta, output_k, key_seed}`. Today one: `N=65536, log_delta=35, output_k=720, key_seed=0` — Poulpy's preset `n16_d35_k720_p19_s2c`, 2¹⁵ slots, scale 2³⁵, sixteen levels restored, 19+ bits of precision |
| Case | one seed. `cases/NNNNNN/case_seed.bin` holds it as a u64, little-endian; that is the whole input. The ciphertext is made from it here, because making it needs the secret |
| Keys | from the point's `key_seed`: the same keys for everybody at a point, and the same keys as every stage's |

Every random stream is `sha256("fherma/ckks-bootstrap/" ‖ seed ‖ "/" ‖ name)`:
`sk`, `xs`, `xe`, `xa` from `key_seed`; `msg`, `input-xa`, `input-xe` from the
case seed. The message is `N/2` points uniform on the unit disc, drawn with
multiplication and comparison only — no libm — so it is the same vector
bit-for-bit on every platform.

## Build

One backend feature, under `[features] default` in `Cargo.toml`:

| Feature | Backend | Needs |
|---|---|---|
| `ifma`, `ifma-rayon` | `NTT3x42Ifma` | AVX-512F + IFMA + VL — **the reference's** |
| `avx512`, `avx512-rayon` | `NTT4x30Avx512` | AVX-512F |
| `avx`, `avx-rayon` | `NTT4x30Avx` | AVX2 + FMA |
| `neon`, `neon-rayon` | `NTT4x30Neon` | aarch64 |
| `ref` | `NTT4x30Ref` | nothing; the portable baseline |

`*-rayon` backends take `threads` from `config.jsonc`. All are exact NTT
backends; Poulpy's approximate FFT64 backends are not offered.

The platform builds with `cargo build --release` in the image
`poulpy-0-8-3` (x86-64 with AVX-512 IFMA; the target features are set by the
image). Locally, another machine builds another backend:

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release                       # whatever Cargo.toml selects
cargo build --release --no-default-features --features neon-rayon            # an Apple M-series
```

## Run locally

The loop and the types come from the signature (any change to them is not
measured); regenerate them with the language tool, then build:

```sh
fherma-lang emit --solution --envelope --out . --force ../ckks-bootstrap-s2c.fkl
cargo build --release --no-default-features --features neon-rayon
```

The binary writes a point directory the way the bundle does:

```sh
./target/release/fherma-solution make point \
  --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1,2,3
./target/release/fherma-solution point
cat point/out/results.json
```

Locally nothing judges the digest, and a digest made on another backend or
operating system will not equal the platform's: Poulpy encodes the DFT
matrices through `f64` and libm at `compile`, and the encoder's FFT differs
between backends at this scale (a Poulpy issue, being fixed). The platform
judges on its own machines, all running the same image and backend. Run
locally to see that it builds, runs, reaches the precision and passes the
composition test; leave the equality to the platform.

## What it costs

At this point, NEON + rayon × 8, Apple M3 Max: `setup` 70 s, one `run`
80–90 s; ref backend, one thread: `run` 230 s. The keys alone are about 18 GB;
the process holds 22–26 GB once they are prepared. Output per case 14 680 129
bytes. Plan for 32 GB and one process at a time. Poulpy's published numbers
for the same preset (Ryzen 9 9950X): ref 39.4 s; AVX-512/IFMA + rayon × 16,
2.29 s; on the platform's RTX PRO 6000 box, IFMA + rayon × 24, about 3.3 s.

## Submitting

Push this directory to a repository. On the platform, create an
implementation of `ckks-bootstrapping` answering `s2c@1.0.0`: repository and
commit, harness language `rust`, runtime image `poulpy-0-8-3`. Run it. The
first run of a new point waits for the reference's own run to produce the
digests; after that a run is judged as it finishes.
