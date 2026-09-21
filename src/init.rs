//! INIT — your setup. Over the point and the context, never a case. NOT
//! measured.
//!
//! The reference's: allocate the output buffer and a working arena. A
//! submission with a GPU would move the keys to the card here; nothing
//! computed here may depend on a case, and the loop never shows it one.
//! (`threads` in `config.jsonc` is read by the envelope's `setup`: the pool
//! is built once, before keygen.)

use poulpy_ckks::layouts::CKKSModuleAlloc;
use poulpy_hal::api::ScratchOwnedAlloc;
use poulpy_hal::layouts::ScratchOwned;

use crate::envelope::backend::BE;
use crate::envelope::{Context, Output};
use crate::fherma::Point;

/// Whatever `init` prepares and `run` needs.
pub struct State<'a> {
    pub context: &'a Context,
    /// Preallocated output; `run` writes into it (as Poulpy's driver does).
    /// At the bootstrap layout: the bootstrap starts at the full width and
    /// leaves the output at `output_k`.
    pub output: Output,
    pub scratch: ScratchOwned<BE>,
}

pub fn init<'a>(point: &Point, context: &'a Context, config: &str) -> State<'a> {
    let _ = (point, config);
    State {
        context,
        output: context
            .module
            .ckks_ciphertext_alloc_from_glwe_infos(&context.preset.bootstrap_layout()),
        scratch: ScratchOwned::<BE>::alloc(context.scratch_bytes),
    }
}
