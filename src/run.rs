//! RUN — the function under measurement. The loop times this call and
//! nothing else.
//!
//! Reference: Poulpy's `ckks_bootstrap_ci_into` on the preset's compiled
//! context and keys (S2C-first: SlotsToCoeffs → ModUp → CoeffsToSlots →
//! EvalMod on the conjugate-invariant ring), from the device's input buffer
//! into its output buffer — where `fherma_h2d` put the case, and where
//! `fherma_d2h` reads the result (both in `init.rs`). On a GPU backend it is
//! the replay of the bootstrap `init` recorded. It returns once the backend
//! has finished, so the time is the bootstrap's and not the time to queue it.
//!
//! A submission with its own algorithm replaces the body of `run`. It must
//! leave the same bytes in the output as this reference does.

use poulpy_hal::api::ModuleSynchronize;

use crate::envelope::{Input, Output};
use crate::init::State;

pub fn run<'a>(state: &'a mut State<'_>, input: &Input) -> &'a Output {
    // The case is already on the device: fherma_h2d put it there.
    let _ = input;
    #[cfg(any(feature = "cuda", feature = "wgpu"))]
    state.replay.replay();
    #[cfg(not(any(feature = "cuda", feature = "wgpu")))]
    crate::init::bootstrap(state.device);
    state.device.module.synchronize();
    // The loop reads the output from fherma_d2h, which brings it to the host.
    &state.host
}
