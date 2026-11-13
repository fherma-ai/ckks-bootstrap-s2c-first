//! ENVELOPE — the specification's side of the measurement, laid over every
//! submission: what turns the point into a context, a case into the input,
//! the output into bytes, and the output into a verdict's metrics. Four
//! functions and three types; the loop (`main.rs`, generated from the
//! signature) calls them around the author's `init` / `run` / `free`.
//!
//! The substance is in the submodules: `keys` (setup — keygen from the
//! point's `key_seed`), `case` (generate: the message from the case's seed,
//! encoded and encrypted), `bytes` (the canonical serialisation), `check`
//! (precision against the message).
//!
//! All of it is on the host. The specification says what goes in and what
//! must come out, and nothing about where the bootstrap runs: the backend, and
//! a device if there is one, are the submission's.

pub mod bytes;
pub mod case;
pub mod check;
pub mod keys;

use crate::fherma::{Inputs, Point};

pub use case::Case;
// What a submission builds on: the client, the keys it moves to its backend.
#[allow(unused_imports)]
pub use keys::{Client, Context, HostCt, HostKeys, CI};

/// Discarded runs before the first timed one.
pub const WARMUP: usize = 3;

/// What `run` receives: the input ciphertext on the host, with the message it
/// encrypts beside it for `check`.
pub type Input = Case;

/// What the submission hands back: the bootstrapped ciphertext — the
/// signature's `ct` — on the host.
pub type Output = HostCt;

/// What `check` says of an output.
pub struct Check {
    pub valid: bool,
    pub metrics: Vec<(&'static str, f64)>,
    pub note: Option<String>,
}

/// The context from the point: keygen from `key_seed`, once, on the host.
/// Not measured. The config is the submission's, read by its `init`.
pub fn setup(point: &Point, config: &str) -> Context {
    let _ = config;
    Context::setup(point)
}

/// Facts about the context, for the report's header.
pub fn describe(context: &Context) -> Vec<(&'static str, String)> {
    vec![
        ("preset", context.preset.name().to_string()),
        ("poulpy", keys::POULPY_VERSION.to_string()),
        ("base2k", context.preset.base2k().to_string()),
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
        && output.meta().slots == input.ct.meta().slots
        && output.meta().log_sparsity == input.ct.meta().log_sparsity
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
