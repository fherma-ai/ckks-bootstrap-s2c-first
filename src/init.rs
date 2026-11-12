//! INIT — your setup. Over the point and the context, never a case. NOT
//! measured.
//!
//! The reference's: allocate the output buffers and the working arenas, one
//! per ring. Nothing computed here may depend on a case, and the loop never
//! shows it one. (`threads` in `config.jsonc` is read by the envelope's
//! `setup`: the pool is built once, before keygen.)

use poulpy_ckks::layouts::CKKSCiphertextAlloc;
use poulpy_hal::api::ScratchOwnedAlloc;
use poulpy_hal::layouts::ScratchOwned;

use crate::envelope::backend::BE;
use crate::envelope::keys::CI;
use crate::envelope::{Context, Ct, Output};
use crate::fherma::Point;

/// Whatever `init` prepares and `run` needs.
pub struct State<'a> {
    pub context: &'a Context,
    /// The bootstrap's output on the backend under test, at the bootstrap
    /// layout: the bootstrap starts at the full width and leaves the output
    /// at `output_k`.
    pub device: Ct,
    /// The same ciphertext on the host: what `run` returns.
    pub output: Output,
    pub scratch: ScratchOwned<BE>,
    pub scratch_ci: ScratchOwned<CI<BE>>,
}

pub fn init<'a>(point: &Point, context: &'a Context, config: &str) -> State<'a> {
    let _ = (point, config);
    let layout = context.preset.bootstrap_layout();
    State {
        context,
        device: context.module.ckks_ciphertext_alloc_from_glwe_infos(&layout),
        output: context.client.ckks_ciphertext_alloc_from_glwe_infos(&layout),
        scratch: ScratchOwned::<BE>::alloc(context.scratch_bytes),
        scratch_ci: ScratchOwned::<CI<BE>>::alloc(context.scratch_ci_bytes),
    }
}
