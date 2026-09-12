//! The backend under test, chosen at build time by a cargo feature.
//!
//! Every backend here is an exact NTT backend: the same seeds produce the same
//! output bytes on each of them, so the digest of the reference (built with
//! `ref`) is the expected answer for all of them — only the time differs.
//! Poulpy's approximate FFT64 backends run the preset at a different radix and
//! would not reproduce the bytes; they are deliberately not offered.

#[cfg(feature = "ref")]
pub type BE = poulpy_cpu_ref::NTT4x30Ref;
#[cfg(feature = "ref")]
pub const NAME: &str = "ntt4x30_ref";

#[cfg(feature = "neon")]
pub type BE = poulpy_cpu_arm::NTT4x30Neon;
#[cfg(feature = "neon")]
pub const NAME: &str = "ntt4x30_neon";

#[cfg(feature = "neon-rayon")]
pub type BE = poulpy_cpu_arm::NTT4x30NeonRayon;
#[cfg(feature = "neon-rayon")]
pub const NAME: &str = "ntt4x30_neon_rayon";

#[cfg(feature = "avx")]
pub type BE = poulpy_cpu_avx::NTT4x30Avx;
#[cfg(feature = "avx")]
pub const NAME: &str = "ntt4x30_avx";

#[cfg(feature = "avx-rayon")]
pub type BE = poulpy_cpu_avx::NTT4x30AvxRayon;
#[cfg(feature = "avx-rayon")]
pub const NAME: &str = "ntt4x30_avx_rayon";

#[cfg(feature = "avx512")]
pub type BE = poulpy_cpu_avx512::NTT4x30Avx512;
#[cfg(feature = "avx512")]
pub const NAME: &str = "ntt4x30_avx512";

#[cfg(feature = "avx512-rayon")]
pub type BE = poulpy_cpu_avx512::NTT4x30Avx512Rayon;
#[cfg(feature = "avx512-rayon")]
pub const NAME: &str = "ntt4x30_avx512_rayon";

#[cfg(feature = "ifma")]
pub type BE = poulpy_cpu_avx512::NTT3x42Ifma;
#[cfg(feature = "ifma")]
pub const NAME: &str = "ntt3x42_ifma";

#[cfg(feature = "ifma-rayon")]
pub type BE = poulpy_cpu_avx512::NTT3x42IfmaRayon;
#[cfg(feature = "ifma-rayon")]
pub const NAME: &str = "ntt3x42_ifma_rayon";

#[cfg(not(any(
    feature = "ref",
    feature = "neon",
    feature = "neon-rayon",
    feature = "avx",
    feature = "avx-rayon",
    feature = "avx512",
    feature = "avx512-rayon",
    feature = "ifma",
    feature = "ifma-rayon",
)))]
compile_error!("select one backend feature: ref (default), neon[-rayon], avx[-rayon], avx512[-rayon], ifma[-rayon]");

// Every backend offered must be exact: an approximate FFT64 backend would run
// the preset at another radix and could not reproduce the bytes.
const _: () = assert!(
    <BE as poulpy_hal::layouts::Backend>::DFT_IS_EXACT,
    "the reference needs an exact (NTT) backend"
);

/// Whether this backend spreads the bootstrap over a rayon pool.
pub const THREADED: bool = cfg!(feature = "threaded");

/// Size the rayon pool for the `*-rayon` backends. No-op otherwise.
pub fn set_threads(threads: usize) {
    #[cfg(feature = "threaded")]
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .expect("rayon global pool is built once, before any work");
    #[cfg(not(feature = "threaded"))]
    let _ = threads;
}
