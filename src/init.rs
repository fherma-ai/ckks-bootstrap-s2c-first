//! INIT — your setup. Over the point and the context, never a case. NOT
//! measured.
//!
//! The reference's: the backend under test (`backend::BE`) compiles the
//! bootstrapping context, receives the keys from the host and prepares them,
//! and allocates the buffers a bootstrap reads and writes and its arenas. A
//! preset with EvalMod on the conjugate-invariant ring takes the `*_ci` calls
//! and a second module, the ring's twin; the others the plain ones. On a GPU
//! backend it also records one bootstrap on those buffers, which `run`
//! replays. Nothing computed here may depend on a case, and the loop never
//! shows it one.
//!
//! Also here, the pair of transfers the loop clocks apart from `run`:
//! `fherma_h2d` moves the case's ciphertext into the buffer the bootstrap
//! reads, `fherma_d2h` brings the output back to the host.

#[path = "backend.rs"]
pub mod backend;

use std::cell::RefCell;

use poulpy_ckks::api::{CKKSBootstrappingCIOps, CKKSBootstrappingOps};
use poulpy_ckks::layouts::{BootstrappingContextPrepared, BootstrappingKeysPrepared, CKKSCiphertextAlloc};
use poulpy_ckks::{CKKSInfos, SetCKKSInfos};
use poulpy_core::api::TransferInto;
use poulpy_core::layouts::{GLWE, LWEInfos, SetK};
use poulpy_hal::api::{ModuleSynchronize, ScratchOwnedAlloc, ScratchOwnedBorrow};
use poulpy_hal::layouts::{Backend, Module, ScratchOwned};

use crate::envelope::keys::conjugate_invariant;
use crate::envelope::{Context, Input, Output, CI};
use crate::fherma::Point;
use backend::BE;

/// A ciphertext on the backend under test.
pub type Ct = poulpy_ckks::layouts::CKKSCiphertextOwned<BE>;

type Buf = <BE as Backend>::OwnedBuf;

/// The compiled context and the prepared keys, as the preset's EvalMod ring
/// needs them.
pub enum Prepared {
    /// EvalMod on the standard ring, at degree N.
    Standard {
        context: BootstrappingContextPrepared<BE, f64>,
        keys: BootstrappingKeysPrepared<Buf, BE>,
    },
    /// EvalMod on the conjugate-invariant ring: the module is at degree 2N,
    /// and `ci` is its twin at N, with an arena of its own.
    ConjugateInvariant {
        ci: Module<CI<BE>>,
        context: BootstrappingContextPrepared<BE, f64>,
        keys: BootstrappingKeysPrepared<Buf, BE, CI<BE>>,
        scratch_ci: RefCell<ScratchOwned<CI<BE>>>,
    },
}

/// What lives on the backend under test for the whole process: the module,
/// the compiled context and the prepared keys, the buffers a bootstrap reads
/// and writes, and its arena. Built once and never dropped (it is `'static`),
/// so that a recorded bootstrap can hold on to the buffers it is bound to.
pub struct Device {
    pub module: Module<BE>,
    pub prepared: Prepared,
    /// The bootstrap's input, at the preset's input layout: `fherma_h2d`
    /// writes the case here.
    pub input: RefCell<Ct>,
    /// The bootstrap's output, allocated at the full bootstrap width: the
    /// bootstrap starts there and leaves the output at `output_k`.
    pub output: RefCell<Ct>,
    pub scratch: RefCell<ScratchOwned<BE>>,
    /// The width the bootstrap starts its output at.
    pub bootstrap_k: usize,
}

/// Whatever `init` prepares and `run` needs.
pub struct State<'a> {
    /// The specification's context, for a submission that wants it in `run`.
    #[allow(dead_code)]
    pub context: &'a Context,
    pub device: &'static Device,
    /// The output on the host: what `fherma_d2h` returns.
    pub host: Output,
    /// One bootstrap recorded on the device's buffers, replayed by `run`.
    #[cfg(any(feature = "cuda", feature = "wgpu"))]
    pub replay: poulpy_gpu_portable::Replay<'static, backend::Runtime>,
}

pub fn init<'a>(point: &Point, context: &'a Context, config: &str) -> State<'a> {
    let _ = point;
    if backend::THREADED {
        backend::set_threads(backend::threads(config));
    }
    let preset = &context.preset;
    let n = preset.n() as u64;
    let keys_layout = preset.keys_layout();
    let input_layout = preset.input_layout();
    let bootstrap_layout = preset.bootstrap_layout();
    let plan = preset.plan();

    let (module, prepared, scratch_bytes) = if conjugate_invariant(preset) {
        let (module, ci) = (Module::<BE>::new(2 * n), Module::<CI<BE>>::new(n));
        // The context, compiled and prepared on the backend.
        let (bytes, bytes_ci) = BootstrappingContextPrepared::<BE, f64>::compile_ci_unprepared_tmp_bytes(&module, &ci, plan)
            .expect("size the compile");
        let unprepared = BootstrappingContextPrepared::<BE, f64>::compile_ci_unprepared(
            &module,
            &ci,
            preset.base2k().into(),
            plan,
            &mut ScratchOwned::<BE>::alloc(bytes).borrow(),
            &mut ScratchOwned::<CI<BE>>::alloc(bytes_ci).borrow(),
        )
        .expect("compile the preset's bootstrapping plan");
        let bytes = unprepared.prepare_tmp_bytes(&module);
        let compiled = unprepared
            .prepare(&module, &mut ScratchOwned::<BE>::alloc(bytes).borrow())
            .expect("prepare the bootstrapping context");
        // The keys, from the host to the backend, prepared there.
        let (bytes, bytes_ci) = keys_layout.prepare_ci_tmp_bytes(&module, &ci);
        let keys = context
            .keys
            .transfer_and_prepare_ci(
                &module,
                &ci,
                &mut ScratchOwned::<BE>::alloc(bytes).borrow(),
                &mut ScratchOwned::<CI<BE>>::alloc(bytes_ci).borrow(),
            )
            .expect("prepare the bootstrapping keys");
        let (scratch_bytes, scratch_ci_bytes) =
            module.ckks_bootstrap_ci_tmp_bytes(&ci, &bootstrap_layout, &input_layout, &compiled, keys_layout);
        let scratch_ci = RefCell::new(ScratchOwned::<CI<BE>>::alloc(scratch_ci_bytes));
        (module, Prepared::ConjugateInvariant { ci, context: compiled, keys, scratch_ci }, scratch_bytes)
    } else {
        let module = Module::<BE>::new(n);
        let bytes = BootstrappingContextPrepared::<BE, f64>::compile_unprepared_tmp_bytes(&module, plan)
            .expect("size the compile");
        let unprepared = BootstrappingContextPrepared::<BE, f64>::compile_unprepared(
            &module,
            preset.base2k().into(),
            plan,
            &mut ScratchOwned::<BE>::alloc(bytes).borrow(),
        )
        .expect("compile the preset's bootstrapping plan");
        let bytes = unprepared.prepare_tmp_bytes(&module);
        let compiled = unprepared
            .prepare(&module, &mut ScratchOwned::<BE>::alloc(bytes).borrow())
            .expect("prepare the bootstrapping context");
        let bytes = keys_layout.prepare_tmp_bytes(&module);
        let keys = context
            .keys
            .transfer_and_prepare(&module, &mut ScratchOwned::<BE>::alloc(bytes).borrow());
        let scratch_bytes = module.ckks_bootstrap_tmp_bytes(&bootstrap_layout, &input_layout, &compiled, keys_layout);
        (module, Prepared::Standard { context: compiled, keys }, scratch_bytes)
    };

    let mut input = module.ckks_ciphertext_alloc_from_glwe_infos(&input_layout);
    input.set_meta(input_layout.meta);
    let output = module.ckks_ciphertext_alloc_from_glwe_infos(&bootstrap_layout);

    let device: &'static Device = Box::leak(Box::new(Device {
        module,
        prepared,
        input: RefCell::new(input),
        output: RefCell::new(output),
        scratch: RefCell::new(ScratchOwned::<BE>::alloc(scratch_bytes)),
        bootstrap_k: preset.bootstrap_k().into(),
    }));

    State {
        context,
        device,
        host: context.client.ckks_ciphertext_alloc_from_glwe_infos(&bootstrap_layout),
        // Recording runs the bootstrap (on whatever the input buffer holds)
        // and keeps its launches; every replay redoes them on these buffers.
        #[cfg(any(feature = "cuda", feature = "wgpu"))]
        replay: poulpy_gpu_portable::Replay::<backend::Runtime>::record(move || bootstrap(device)),
    }
}

/// One bootstrap of the device's input into its output, queued: on a GPU it
/// may still be running when this returns. Poulpy's `bootstrap_queued`. The
/// output is set back to the full width first, which also makes every call
/// the same, as a recording needs.
pub fn bootstrap(device: &Device) {
    let mut output = device.output.borrow_mut();
    output.set_k(device.bootstrap_k.into());
    let input = device.input.borrow();
    let mut scratch = device.scratch.borrow_mut();
    match &device.prepared {
        Prepared::Standard { context, keys } => device
            .module
            .ckks_bootstrap(&mut *output, &*input, context, keys, &mut scratch.borrow()),
        Prepared::ConjugateInvariant { ci, context, keys, scratch_ci } => device.module.ckks_bootstrap_ci_into(
            ci,
            &mut *output,
            &*input,
            context,
            keys,
            &mut scratch.borrow(),
            &mut scratch_ci.borrow_mut().borrow(),
        ),
    }
    .expect("bootstrap");
}

impl State<'_> {
    /// Host to device: the case's ciphertext into the buffer the bootstrap
    /// reads. Clocked by the loop on its own, not the score.
    pub fn fherma_h2d(&mut self, input: &Input) {
        let mut on_device = self.device.input.borrow_mut();
        let glwe: &GLWE<_, _> = &input.ct;
        glwe.transfer_into(&mut **on_device);
        on_device.set_meta(input.ct.meta());
        drop(on_device);
        self.device.module.synchronize();
    }

    /// Device to host: the bootstrap's output, at the width it was left at.
    /// Clocked by the loop on its own, not the score.
    pub fn fherma_d2h(&mut self) -> &Output {
        let on_device = self.device.output.borrow();
        self.host.set_k(on_device.k());
        let glwe: &GLWE<_, _> = &on_device;
        glwe.transfer_into(&mut *self.host);
        self.host.set_meta(on_device.meta());
        &self.host
    }
}
