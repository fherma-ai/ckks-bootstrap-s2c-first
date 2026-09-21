//! ENVELOPE — the specification's side of the measurement, laid over every
//! submission: what turns the point into a context, a case into the input,
//! the output into bytes, and the output into a verdict's metrics. Four
//! functions and three types; the loop (`main.rs`, generated from the
//! signature) calls them around the author's `init` / `run` / `free`.
//!
//! The substance is in the submodules: `keys` (setup — keygen from the
//! point's `key_seed`), `case` (generate: the message from the case's seed,
//! encoded and encrypted), `bytes` (the canonical serialisation), `check`
//! (precision against the message), `backend` (which Poulpy backend, by
//! cargo feature).

pub mod backend;
pub mod bytes;
pub mod case;
pub mod check;
pub mod keys;

use crate::fherma::{Inputs, Point};

pub use case::Case;
pub use keys::{Context, Ct};

/// Discarded runs before the first timed one.
pub const WARMUP: usize = 3;

/// What `run` receives: the input ciphertext, with the message it encrypts
/// beside it for `check`.
pub type Input = Case;

/// What `run` leaves: the bootstrapped ciphertext — the signature's `ct`.
pub type Output = Ct;

/// What `check` says of an output.
pub struct Check {
    pub valid: bool,
    pub metrics: Vec<(&'static str, f64)>,
    pub note: Option<String>,
}

/// The context from the point: keygen from `key_seed`, once. Not measured.
/// The worker pool of a `*-rayon` backend is sized here, from the solution's
/// `config.jsonc` (`threads`; 0 or absent is every core): it is built once
/// per process, before any work, and keygen is work.
pub fn setup(point: &Point, config: &str) -> Context {
    if backend::THREADED {
        backend::set_threads(threads(config));
    }
    Context::setup(point)
}

/// `threads` from `config.jsonc`; 0 or absent is every core.
fn threads(config: &str) -> usize {
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

/// Facts about the context, for the report's header.
pub fn describe(context: &Context) -> Vec<(&'static str, String)> {
    vec![
        ("preset", context.preset.name().to_string()),
        ("poulpy", keys::POULPY_VERSION.to_string()),
        ("backend", backend::NAME.to_string()),
    ]
}

/// The case from its inputs: the message encrypted at the input layout. Not measured.
pub fn generate(context: &Context, inputs: &Inputs) -> Input {
    case::generate(context, inputs)
}

/// The output as the bytes the platform hashes: one entry, the signature's `ct`.
pub fn serialize(output: &Output) -> Vec<(&'static str, Vec<u8>)> {
    vec![("ct", bytes::bytes(output))]
}

/// Whether the output has the shape a bootstrap leaves — the input's ring,
/// slots and sparsity, back at the application scale, at least the width
/// the point asks for — and how many bits of the message survived.
pub fn check(context: &Context, input: &Input, output: &Output) -> Check {
    use poulpy_ckks::CKKSInfos;
    use poulpy_core::layouts::{GLWEInfos, LWEInfos};

    let shaped = output.n() == input.ct.n()
        && output.rank() == input.ct.rank()
        && output.base2k() == input.ct.base2k()
        && output.slots() == input.ct.slots()
        && output.log_sparsity() == input.ct.log_sparsity()
        && output.log_delta() == input.ct.log_delta()
        && output.k().as_usize() >= context.preset.output_k();
    let precision = check::precision(context, output, &input.re, &input.im);
    Check {
        valid: shaped && precision.max_abs_err.is_finite(),
        metrics: vec![
            ("precision_bits", precision.re_min_bits.min(precision.im_min_bits)),
            ("precision_bits_avg", (precision.re_avg_bits + precision.im_avg_bits) / 2.0),
            ("precision_bits_re", precision.re_min_bits),
            ("precision_bits_im", precision.im_min_bits),
            ("max_abs_err", precision.max_abs_err),
        ],
        note: None,
    }
}
