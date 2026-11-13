//! The backend the bootstrap runs on, chosen at build time by a cargo
//! feature. The submission's file: the specification's client stays
//! `NTT4x30Portable` on the host whatever is chosen here.
//!
//! Every backend here is an exact NTT backend: at one radix the same seeds
//! produce the same output bytes on each of them, so the digest of the
//! reference (built with `ifma-rayon`, as `Cargo.toml` defaults) is the
//! expected answer for all of them — only the time differs. The GPU backends
//! run the NTT4x30 arithmetic of the CPU ones, bit-identical to
//! `NTT4x30Portable` (poulpy-gpu-portable's README).
//! Poulpy's approximate FFT64 backends run the preset at a different radix and
//! would not reproduce the bytes; they are deliberately not offered.
#![allow(dead_code)] // `NAME` is for a submission that reports its backend

#[cfg(feature = "ref")]
pub type BE = poulpy_cpu_portable::NTT4x30Portable;
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

#[cfg(feature = "cuda")]
pub type BE = poulpy_gpu_portable::NTT4x30Cuda;
#[cfg(feature = "cuda")]
pub const NAME: &str = "ntt4x30_cuda";

// Metal, Vulkan or WebGPU through wgpu: for trying a GPU submission on a
// laptop. The platform's GPU machines are NVIDIA, and run `cuda`.
#[cfg(feature = "wgpu")]
pub type BE = poulpy_gpu_portable::NTT4x30Wgpu;
#[cfg(feature = "wgpu")]
pub const NAME: &str = "ntt4x30_wgpu";

/// The GPU runtime a bootstrap is recorded on and replayed, as one graph
/// where the runtime has graphs (`poulpy_gpu_portable::Replay`).
#[cfg(feature = "cuda")]
pub type Runtime = poulpy_gpu_portable::Cuda;
#[cfg(feature = "wgpu")]
pub type Runtime = poulpy_gpu_portable::Wgpu;

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
    feature = "cuda",
    feature = "wgpu",
)))]
compile_error!("select one backend feature: ref, neon[-rayon], avx[-rayon], avx512[-rayon], ifma[-rayon] (default), cuda, wgpu");

// Every backend offered must be exact: an approximate FFT64 backend would run
// the preset at another radix and could not reproduce the bytes. 0.8.3 let the
// backend say so — `Backend::DFT_IS_EXACT` — and 0.9.0 removed the flag, which
// its changelog calls a workaround for an FFT64 bug rather than a statement
// about the transform. The guarantee is now the feature list above: every one
// of them selects an NTT backend, and selecting none is a compile error.

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

/// `threads` from `config.jsonc`; 0 or absent is every core.
pub fn threads(config: &str) -> usize {
    let all = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let text: String = config
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    text.find("\"threads\"")
        .and_then(|at| text[at..].find(':').map(|colon| at + colon + 1))
        .and_then(|from| {
            let rest = text[from..].trim_start();
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse::<usize>().ok()
        })
        .filter(|&t| t > 0)
        .unwrap_or(all)
}
