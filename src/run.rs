//! RUN — the function under measurement. The loop times this call and
//! nothing else.
//!
//! Reference: Poulpy's `ckks_bootstrap_ci_into` on the preset's compiled
//! context and keys (S2C-first: SlotsToCoeffs → ModUp → CoeffsToSlots →
//! EvalMod on the conjugate-invariant ring), then the result moved to the
//! host. On a CPU backend the move is a copy; on a GPU it waits for the
//! device, so the time is the bootstrap's and not the time to queue it.
//!
//! A submission with its own algorithm replaces the body of `run`. It gets
//! its state from `init` and the input ciphertext, and must leave the same
//! bytes in the host output as this reference does.

use poulpy_ckks::api::CKKSBootstrappingCIOps;
use poulpy_ckks::{CKKSInfos, SetCKKSInfos};
use poulpy_core::api::TransferInto;
use poulpy_core::layouts::{GLWE, LWEInfos, SetK};
use poulpy_hal::api::ScratchOwnedBorrow;

use crate::envelope::{Input, Output};
use crate::init::State;

pub fn run<'a>(state: &'a mut State<'_>, input: &Input) -> &'a Output {
    let context = state.context;
    let State {
        device,
        output,
        scratch,
        scratch_ci,
        ..
    } = state;

    // The bootstrap consumes width: it starts at the preset's bootstrap width
    // and leaves the output at `output_k`. The buffer is reused, so it is set
    // back to the full width before every run.
    device.set_k(context.preset.bootstrap_k().into());
    context
        .module
        .ckks_bootstrap_ci_into(
            &context.ci,
            device,
            &input.ct,
            &context.context,
            &context.keys,
            &mut scratch.borrow(),
            &mut scratch_ci.borrow(),
        )
        .expect("bootstrap");

    output.set_k(device.k());
    let glwe: &GLWE<_, _> = device;
    glwe.transfer_into(&mut **output);
    output.set_meta(device.meta());
    output
}
