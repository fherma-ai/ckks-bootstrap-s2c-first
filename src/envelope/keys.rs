//! SETUP — the context from the point. NOT measured.
//!
//! `setup(point)` does keygen once per benchmark point: picks the Poulpy
//! preset the point names, then the modules, the compiled bootstrapping
//! context, the secret and the bootstrapping keys — from the point's
//! `key_seed`. The specification's file, laid over every submission.
//!
//! Two roles, as in Poulpy 0.10.0's own preset driver
//! (`poulpy_ckks::test_suite::presets::BootstrappingPresetRun::setup_ci`, the
//! code behind its benchmarks), with seeds in place of constants:
//!
//! - the client, `NTT4x30Portable` on the host, samples the secret, generates
//!   the keys, encrypts every case and decrypts every output;
//! - the backend under test (`backend::BE`, a CPU backend or a GPU) compiles
//!   the context, receives the keys and prepares them, and bootstraps.
//!
//! The client is the same on every backend, and the preset is taken at the
//! radix of the NTT4x30 arithmetic on every backend, so the keys, the inputs
//! and the expected bytes are the same whichever backend a submission picks.

use sha2::{Digest, Sha256};

use poulpy_ckks::api::{CKKSAllOpsTmpBytes, CKKSBootstrappingCIOps};
use poulpy_ckks::layouts::{BootstrappingContextPrepared, BootstrappingKeysPrepared, BootstrappingPipeline};
use poulpy_ckks::presets::bootstrapping::{all, BootstrappingPreset};
use poulpy_ckks::{CKKSLayout, GLWEPlaintextMeta, Scale, SlotsKind};

use poulpy_core::api::{GLWESecretPreparedFactory, GLWESecretSampling};
use poulpy_core::layouts::{BackendGLWESecretPrepared, GLWELayout, GLWESecretAlloc, Rank};

use poulpy_hal::api::{ScratchOwnedAlloc, ScratchOwnedBorrow};
use poulpy_hal::layouts::{Backend, MaxBase2k, Module, ScratchOwned};
use poulpy_hal::source::Source;

use std::cell::RefCell;

use crate::envelope::backend::{Client, BE};
use crate::fherma::Point;

/// The conjugate-invariant twin of a backend: EvalMod runs on it.
pub type CI<B> = <Module<B> as CKKSBootstrappingCIOps<B>>::CI;

/// A ciphertext on the backend under test: what `run` receives.
pub type Ct = poulpy_ckks::layouts::CKKSCiphertextOwned<BE>;

/// A ciphertext on the host, on the client: what `run` returns. A backend on
/// a device moves its output here inside `run`, so the time `run` takes
/// includes all the work the bootstrap queued.
pub type HostCt = poulpy_ckks::layouts::CKKSCiphertextOwned<Client>;

/// The specification: the circuit. Everything else — sizes, widths, key
/// layout, hamming weights — comes with the preset the point selects.
pub const PIPELINE: BootstrappingPipeline = BootstrappingPipeline::S2CFirst;

/// Failure probability of one bootstrap the radix is chosen for, `2^-128`:
/// Poulpy's `BOOTSTRAP_FAILURE_BITS`, the one its benchmarks are run at.
const FAILURE_BITS: usize = 128;

/// The Poulpy preset for a point: the one with this pipeline and these sizes,
/// with the keys of power-of-two rotations only, at the largest radix the
/// NTT4x30 arithmetic takes for a failure probability of `2^-128` — the
/// configuration Poulpy's `ckks_bootstrapping` benchmark names
/// `<preset>+pow2`. A point Poulpy ships no preset for is not a point of this
/// specification.
pub fn preset_for(point: &Point) -> Result<BootstrappingPreset, String> {
    let presets = all().map_err(|e| format!("poulpy presets: {e}"))?;
    let nominal = presets
        .into_iter()
        .find(|p| {
            p.plan().pipeline() == PIPELINE
                && p.n() == point.N as usize
                && p.log_delta() == point.log_delta as usize
                && p.output_k() == point.output_k as usize
        })
        .ok_or_else(|| {
            format!(
                "no {PIPELINE:?} preset for N={} log_delta={} output_k={} in poulpy-ckks {}",
                point.N, point.log_delta, point.output_k, POULPY_VERSION
            )
        })?;
    let pow2 = nominal.with_power_of_two_keys().map_err(|e| format!("power-of-two keys: {e}"))?;
    at_radix::<Client, CI<Client>>(&pow2).map_err(|e| format!("radix: {e}"))
}

/// Poulpy's `test_suite::presets::preset_for_backend`: the preset at the
/// largest radix `B` and its twin take, re-derived above the nominal one and
/// capped below it.
fn at_radix<B: MaxBase2k, BCI: MaxBase2k>(preset: &BootstrappingPreset) -> anyhow::Result<BootstrappingPreset> {
    let max = preset.max_backend_base2k::<B, BCI>(FAILURE_BITS);
    if max > preset.base2k() {
        preset.with_backend_base2k::<B, BCI>(FAILURE_BITS)
    } else if preset.base2k() > max {
        preset.with_base2k(max)?.with_dsizes(7, 1)
    } else {
        Ok(preset.clone())
    }
}

/// The Poulpy release the harness is written against (pinned in Cargo.toml).
pub const POULPY_VERSION: &str = "0.10.0";

/// The context: everything the envelope makes from the point, and what the
/// author's `init` is handed. Public material — the modules, the compiled
/// bootstrapping context, the prepared keys, the scratch sizes — and, for the
/// envelope's own use, the client, its secret and its arena.
pub struct Context {
    pub preset: BootstrappingPreset,
    /// The backend under test, at degree `2N`: one module serves the ring
    /// conversions and the stages of degree `N`.
    pub module: Module<BE>,
    /// Its conjugate-invariant twin, at degree `N`, for EvalMod.
    pub ci: Module<CI<BE>>,
    pub context: BootstrappingContextPrepared<BE, f64>,
    pub keys: BootstrappingKeysPrepared<<BE as Backend>::OwnedBuf, BE, CI<BE>>,
    /// The working memory one bootstrap needs on each ring, as Poulpy's
    /// `ckks_bootstrap_ci_tmp_bytes` states it: what the author's `init`
    /// sizes its arenas by.
    pub scratch_bytes: usize,
    pub scratch_ci_bytes: usize,
    /// The host side: keygen, encryption, decryption.
    pub client: Module<Client>,
    pub(crate) client_scratch: RefCell<ScratchOwned<Client>>,
    /// The secret `generate` encrypts with. Derivable from the point's
    /// `key_seed` by anyone; correctness is byte equality, so it needs no guarding.
    pub(crate) sk: BackendGLWESecretPrepared<Client>,
    pub(crate) input_layout: CKKSLayout,
}

impl Context {
    /// keygen from the point's key-seed. Once per benchmark point.
    pub fn setup(point: &Point) -> Self {
        let preset = preset_for(point).unwrap_or_else(|e| panic!("{e}"));
        let key_seed = point.key_seed;
        let n = preset.n() as u64;
        let (module, ci) = (Module::<BE>::new(2 * n), Module::<CI<BE>>::new(n));
        let (client, client_ci) = (Module::<Client>::new(2 * n), Module::<CI<Client>>::new(n));
        let keys_layout = preset.keys_layout();
        let input_layout = preset.input_layout();
        let bootstrap_layout = preset.bootstrap_layout();

        // Dense application secret at the preset's Hamming weight.
        let sk_layout = bootstrap_layout.glwe_layout;
        let mut sk_raw = client.glwe_secret_alloc_from_infos(&sk_layout);
        client.glwe_secret_fill_ternary_hw(
            &mut sk_raw,
            preset.dense_secret_hamming_weight(),
            &mut Source::new(seed32(key_seed, "sk")),
        );
        let mut sk = client.glwe_secret_prepared_alloc_from_infos(&sk_layout);
        client.glwe_secret_prepare(&mut sk, &sk_raw);

        // The keys, on the client.
        let (bytes, bytes_ci) = keys_layout.generate_ci_tmp_bytes(&client, &client_ci);
        let mut source_xs = Source::new(seed32(key_seed, "xs"));
        let mut source_xa = Source::new(seed32(key_seed, "xa"));
        let mut source_xe = Source::new(seed32(key_seed, "xe"));
        let keys = preset
            .plan()
            .generate_keys_ci(
                &client,
                &client_ci,
                &sk_raw,
                keys_layout,
                &mut source_xs,
                &mut source_xe,
                &mut source_xa,
                &mut ScratchOwned::<Client>::alloc(bytes).borrow(),
                &mut ScratchOwned::<CI<Client>>::alloc(bytes_ci).borrow(),
            )
            .expect("generate the bootstrapping keys");

        // The context, on the backend under test.
        let plan = preset.plan();
        let (bytes, bytes_ci) =
            BootstrappingContextPrepared::<BE, f64>::compile_ci_unprepared_tmp_bytes(&module, &ci, plan)
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
        let context = unprepared
            .prepare(&module, &mut ScratchOwned::<BE>::alloc(bytes).borrow())
            .expect("prepare the bootstrapping context");

        // The keys, moved to the backend under test and prepared there; the
        // client's copies are dropped with `keys` at the end of this scope.
        let (bytes, bytes_ci) = keys_layout.prepare_ci_tmp_bytes(&module, &ci);
        let prepared = keys
            .transfer_and_prepare_ci(
                &module,
                &ci,
                &mut ScratchOwned::<BE>::alloc(bytes).borrow(),
                &mut ScratchOwned::<CI<BE>>::alloc(bytes_ci).borrow(),
            )
            .expect("prepare the bootstrapping keys");
        drop(keys);

        let (scratch_bytes, scratch_ci_bytes) =
            module.ckks_bootstrap_ci_tmp_bytes(&ci, &bootstrap_layout, &input_layout, &context, keys_layout);
        let client_scratch = ScratchOwned::<Client>::alloc(client_tmp_bytes(&client, &preset));

        Context {
            preset,
            module,
            ci,
            context,
            keys: prepared,
            scratch_bytes,
            scratch_ci_bytes,
            client,
            client_scratch: RefCell::new(client_scratch),
            sk,
            input_layout,
        }
    }
}

/// The client's arena: encoding, encryption, decryption and decoding at the
/// bootstrap layout (Poulpy's `bootstrap_setup_tmp_bytes`).
fn client_tmp_bytes(client: &Module<Client>, preset: &BootstrappingPreset) -> usize {
    let layout = preset.bootstrap_layout();
    let coeffs = preset.plan().eval_mod().coeffs_meta;
    let coeffs = ckks_spec(
        preset.n(),
        preset.base2k(),
        coeffs.log_delta(),
        coeffs.log_budget(),
    );
    let keys = preset.keys_layout();
    keys.rotation_key_layouts()
        .iter()
        .map(|atk| client.ckks_all_ops_with_atk_tmp_bytes(&layout, &coeffs, &keys.tensor_key, atk))
        .max()
        .unwrap_or(0)
}

/// A 32-byte seed for a named randomness stream under an integer root. The
/// streams a pipeline draws from (secret, ephemeral secret, key error, key
/// mask; message, input mask, input error) are kept apart, all fixed by the
/// platform's seeds.
pub(crate) fn seed32(root: u64, stream: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"fherma/ckks-bootstrap/");
    h.update(root.to_le_bytes());
    h.update(b"/");
    h.update(stream.as_bytes());
    h.finalize().into()
}

/// A CKKS layout from widths (Poulpy's `test_suite::helpers::ckks_spec`).
fn ckks_spec(n: usize, base2k: usize, log_delta: usize, log_budget: usize) -> CKKSLayout {
    CKKSLayout {
        glwe_layout: GLWELayout {
            n: n.into(),
            base2k: base2k.into(),
            k: (log_delta + log_budget).into(),
            rank: Rank(1),
        },
        meta: GLWEPlaintextMeta {
            scale: Scale::Log(log_delta),
            slots: SlotsKind::Complex,
            log_sparsity: 0,
        },
    }
}
