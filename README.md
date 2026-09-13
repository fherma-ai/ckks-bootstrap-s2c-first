# CKKS bootstrapping, S2C-first — a submission

A submission to the specification `ckks-bootstrapping/s2c@1.0.0`: one call to
Poulpy's S2C-first bootstrapping (`SlotsToCoeffs → ModUp → CoeffsToSlots →
EvalMod`) on one ciphertext, timed. Poulpy 0.8.3, toolchain
`nightly-2026-05-14`.

This directory is the harness the platform measures every submission in. The
reference implementation is this harness with `src/run.rs` as it ships. A
submission that keeps `run.rs` competes on backend and threads; one that
replaces it competes on the algorithm and must produce the same bytes.

## Files

| File | Owner | Role |
|---|---|---|
| `src/run.rs` | **you** | `run(state, input)` — the bootstrap. The only thing timed. |
| `Cargo.toml` | **you** | the backend, as one cargo feature under `[features] default` |
| `config.jsonc` | **you** | `threads`, for a `*-rayon` backend |
| `rust-toolchain.toml` | you | `nightly-2026-05-14`; Poulpy needs nightly |
| `src/fherma.rs` | platform, generated | the types, from the specification's signature: `Point {N, log_delta, output_k, key_seed}`, `Inputs {case_seed}`, `Outputs {ct}` — the harness carries no copy of its own |
| `src/init.rs` | platform | `State::init(&Point)`: the preset for the point, the module, the compiled bootstrapping context, secret and keys from `key_seed` |
| `src/generate.rs` | platform | `generate(state, &Inputs)`: the case from its seed — message, encryption mask, error |
| `src/main.rs` | platform | the loop: point directory in, `out/` and `results.json` out, the clock around `run` |
| `src/digest.rs` | platform | the output ciphertext as canonical bytes, and its sha256 |
| `src/check.rs` | platform | decrypts the output and measures its precision against the message |
| `src/backend.rs` | platform | the backend's name, from the cargo feature |

The platform's files are marked GENERATED. They are laid over your repository
at every measurement, so a change to them is not measured. `fherma
implementation init … --update` refreshes them when the harness moves and
never touches yours.

## What is measured

One call to `run` per case, wall-clock seconds, after three discarded warm-up
calls on the first case. Every other stage is timed and reported beside it,
and none of them is the score:

| In `out/results.json` | Seconds spent |
|---|---|
| `init_s` | keygen and compiling the bootstrapping context, once |
| `warmup_s` | the three warm-up calls, once |
| per case `generate_s` | the case from its seed |
| per case `seconds` | **the score**: one `run` |
| per case `digest_s`, `write_s` | serialising the output and writing it |
| per case `check_s` | decrypting the output for its precision |
| `max_rss_bytes` | the process's peak resident memory, bytes |

## How correctness is judged

By digest against the reference. The output ciphertext is serialised
canonically — `"fherma/ckks-ct/v1"`, then `n, cols, base2k, k, log_delta,
slots` as little-endian u64, then the limbs carrying the current `k` bits of
every column as little-endian i64 — and written as `out/NNNNNN/ct.bin`. The
platform takes its sha256 and compares it with the one the reference produced
for the same point and seed. Equal is a pass; there is no tolerance. Poulpy's
exact NTT backends produce the same limbs for the same seeds, so one
reference answer serves every backend.

Each case's row also carries `metrics`: `precision_bits` (the worst slot, real
or imaginary part), `precision_bits_avg`, `precision_bits_re`,
`precision_bits_im`, `max_abs_err` — measured against the message, reported,
not judged.

## The point and the case

| | |
|---|---|
| Point | `{N, log_delta, output_k, key_seed}`. Today one: `N=65536, log_delta=35, output_k=720, key_seed=0` — Poulpy's preset `n16_d35_k720_p19_s2c`, 2¹⁵ slots, scale 2³⁵, sixteen levels restored, 19+ bits of precision |
| Case | one seed. `cases/NNNNNN/case_seed.bin` holds it as a u64, little-endian; that is the whole input. The ciphertext is made from it here, because making it needs the secret |
| Keys | from the point's `key_seed`: the same keys for everybody at a point |

Every random stream is `sha256("fherma/ckks-bootstrap/" ‖ seed ‖ "/" ‖ name)`:
`sk`, `xs`, `xe`, `xa` from `key_seed`; `msg`, `input-xa`, `input-xe` from the
case seed. The message is `N/2` points uniform on the unit disc, drawn with
multiplication and comparison only — no libm — so it is the same vector
bit-for-bit on every platform.

## Build

One backend feature, under `[features] default` in `Cargo.toml`:

| Feature | Backend | Needs |
|---|---|---|
| `ref` | `NTT4x30Ref` | nothing; the portable baseline |
| `avx`, `avx-rayon` | `NTT4x30Avx` | AVX2 + FMA |
| `avx512`, `avx512-rayon` | `NTT4x30Avx512` | AVX-512F |
| `ifma`, `ifma-rayon` | `NTT3x42Ifma` | AVX-512F + IFMA + VL |
| `neon`, `neon-rayon` | `NTT4x30Neon` | aarch64 |

`*-rayon` backends take `threads` from `config.jsonc`. All are exact NTT
backends; Poulpy's approximate FFT64 backends run the preset at another radix
and are not offered.

The platform builds with `cargo build --release` in the image
`poulpy-0-8-3` (x86-64 with AVX-512 IFMA; every backend warm; the target
features are set by the image). Locally the AVX crates need the same flags:

```sh
cargo build --release                                                        # ref
RUSTFLAGS="-C target-cpu=native" cargo build --release                       # whatever Cargo.toml selects
```

## Run locally

With the specification's bundle beside this directory:

```sh
fherma implementation run --bundle ../ckks-bootstrap-s2c-bundle \
  --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1
```

Or by hand — the binary writes a point directory the way the bundle does:

```sh
cargo build --release
./target/release/fherma-solution make point \
  --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1,2,3
./target/release/fherma-solution point
cat point/out/results.json
shasum -a 256 point/out/000000/ct.bin          # equals the row's digest
```

Locally nothing judges the digest; compare it with the reference's for the
same point and seed. On the platform the comparison is automatic.

## What it costs

At this point, ref backend, one thread, Apple M-series: `init` 110 s, the
three warm-ups 670 s, one `run` 230 s. The keys alone are about 18 GB; the
process holds 22–26 GB once they are prepared, and `init` prepares them one
at a time so that it never holds two copies (Poulpy's own `prepare` does, and
peaks near 40 GB). Output per case 14 680 129 bytes. Plan for 32 GB and one
process at a time. Poulpy's published numbers for the same preset (Ryzen 9
9950X): ref 39.4 s; AVX-512/IFMA + rayon × 16, 2.29 s.

## Submitting

Push this directory to a repository. On the platform, create an
implementation of `ckks-bootstrapping` answering `s2c@1.0.0`: repository and
commit, harness language `rust`, runtime image `poulpy-0-8-3`. Run it. The
first run of a new point waits for the reference's own run to produce the
digests; after that a run is judged as it finishes.
