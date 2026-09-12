//! CHECK — the output's precision against the message it was made from. NOT
//! measured as score; timed apart and reported as metrics.
//!
//! Correctness on the platform is the digest. This is the other half of what
//! a bootstrapping is judged by: how many bits of the message survive. The
//! same measurement as Poulpy's own preset driver
//! (`test_suite::presets::BootstrappingPresetRun::precision`): decrypt the
//! output at a small budget above `log_delta`, decode to `(re, im)`, and take
//! `-log2` of the absolute error — the worst slot and the average. The
//! platform owns this file; it has the secret because `init` does.

use poulpy_ckks::api::{CKKSDecryptOps, CKKSEncodingHostOps};
use poulpy_ckks::layouts::CKKSModuleAlloc;
use poulpy_ckks::{CKKSInfos, CKKSMeta, SetCKKSInfos, SlotsKind};
use poulpy_core::layouts::LWEInfos;
use poulpy_hal::api::ScratchOwnedBorrow;

use crate::init::State;

/// Plaintext budget bits above `log_delta` the output is decrypted at, as in
/// Poulpy's driver.
const LOG_BUDGET: usize = 8;

/// Bits of precision, over every slot: the worst one and the average, for the
/// real and the imaginary parts, and the largest absolute error.
#[derive(Clone, Copy, Debug)]
pub struct Precision {
    pub re_min_bits: f64,
    pub re_avg_bits: f64,
    pub im_min_bits: f64,
    pub im_avg_bits: f64,
    pub max_abs_err: f64,
}

/// Decrypts `state.output` and measures it against the message the case was
/// made from.
pub fn precision(state: &mut State, want_re: &[f64], want_im: &[f64]) -> Precision {
    let output = &state.output;
    let log_delta = output.log_delta();
    let log_budget = output
        .log_budget()
        .min(LOG_BUDGET)
        .min(127usize.saturating_sub(log_delta));

    let mut pt = state
        .module
        .ckks_pt_vec_alloc(output.base2k(), (log_delta + log_budget).into());
    pt.set_meta(CKKSMeta {
        log_sparsity: 0,
        log_delta,
        slots: SlotsKind::Complex,
    });
    state
        .module
        .ckks_decrypt(&mut pt, output, &state.sk, &mut state.scratch.borrow())
        .expect("decrypt the output for the precision check");

    let m = want_re.len();
    let (mut got_re, mut got_im) = (vec![0.0f64; m], vec![0.0f64; m]);
    state
        .module
        .ckks_decode_reim_into(&pt, &mut got_re, &mut got_im, &mut state.scratch.borrow())
        .expect("decode the output for the precision check");

    let re = stats(&got_re, want_re, log_delta);
    let im = stats(&got_im, want_im, log_delta);
    Precision {
        re_min_bits: re.0,
        re_avg_bits: re.1,
        im_min_bits: im.0,
        im_avg_bits: im.1,
        max_abs_err: re.2.max(im.2),
    }
}

/// `(min bits, average bits, max absolute error)`, Poulpy's `precision_stats`.
fn stats(got: &[f64], want: &[f64], log_delta: usize) -> (f64, f64, f64) {
    let mut sum = 0.0f64;
    let mut max = 0.0f64;
    for (g, w) in got.iter().zip(want) {
        let err = (g - w).abs();
        sum += err;
        if err > max {
            max = err;
        }
    }
    let bits = |err: f64| -> f64 {
        let err = if err <= 0.0 { (-(log_delta as f64)).exp2() } else { err };
        -err.log2()
    };
    (bits(max), bits(sum / got.len().max(1) as f64), max)
}
