//! RUN — the function under measurement. The wrapper times this call and
//! nothing else.
//!
//! Reference: Poulpy's `ckks_bootstrap` on the preset's compiled context and
//! keys (S2C-first: SlotsToCoeffs → ModUp → CoeffsToSlots → EvalMod). The same
//! two statements as Poulpy's benchmark driver.
//!
//! A submission with its own algorithm replaces the body of `run`. It gets the
//! state from `init` (module, context, keys, scratch, output buffer) and the
//! input ciphertext, and must leave the same bytes in `state.output` as this
//! reference does (checked by `digest`).

use poulpy_ckks::api::CKKSBootstrappingOps;
use poulpy_ckks::SetCKKSInfos;
use poulpy_hal::api::ScratchOwnedBorrow;

use crate::init::{Ct, State};

pub fn run(state: &mut State, input: &Ct) {
    // The bootstrap consumes width: it starts at the preset's bootstrap width
    // and leaves the output at `output_k`. The buffer is reused, so it is set
    // back to the full width before every run.
    state.output.set_k(state.preset.bootstrap_k().into());
    state
        .module
        .ckks_bootstrap(
            &mut state.output,
            input,
            &state.context,
            &state.keys,
            &mut state.scratch.borrow(),
        )
        .expect("bootstrap");
}
