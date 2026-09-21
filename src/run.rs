//! RUN — the function under measurement. The loop times this call and
//! nothing else.
//!
//! Reference: Poulpy's `ckks_bootstrap` on the preset's compiled context and
//! keys (S2C-first: SlotsToCoeffs → ModUp → CoeffsToSlots → EvalMod). The same
//! two statements as Poulpy's benchmark driver.
//!
//! A submission with its own algorithm replaces the body of `run`. It gets
//! its state from `init` and the input ciphertext, and must leave the same
//! bytes in the output as this reference does.

use poulpy_ckks::api::CKKSBootstrappingOps;
use poulpy_ckks::SetCKKSInfos;
use poulpy_hal::api::ScratchOwnedBorrow;

use crate::envelope::{Input, Output};
use crate::init::State;

pub fn run<'a>(state: &'a mut State<'_>, input: &Input) -> &'a Output {
    let context = state.context;
    let State { output, scratch, .. } = state;

    // The bootstrap consumes width: it starts at the preset's bootstrap width
    // and leaves the output at `output_k`. The buffer is reused, so it is set
    // back to the full width before every run.
    output.set_k(context.preset.bootstrap_k().into());
    context
        .module
        .ckks_bootstrap(output, &input.ct, &context.context, &context.keys, &mut scratch.borrow())
        .expect("bootstrap");
    output
}
