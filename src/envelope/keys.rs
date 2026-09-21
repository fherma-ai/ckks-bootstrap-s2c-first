//! SETUP — the context from the point. NOT measured.
//!
//! `setup(point)` does keygen once per benchmark point: picks the Poulpy
//! preset the point names, then module, compiled bootstrapping context,
//! secret, bootstrapping keys — from the point's `key_seed`. Every key
//! stream is derived from `key_seed`, so the same point gives the same keys
//! on any machine and any exact backend. The specification's file, laid over
//! every submission; the same keygen as the bootstrapping's.
//!
//! Same calls as Poulpy 0.8.3's own preset driver
//! (`poulpy_ckks::test_suite::presets::BootstrappingPresetRun`, the code behind
//! https://www.poulpy.dev/benchmarks/), with seeds in place of constants.

use sha2::{Digest, Sha256};

use poulpy_ckks::api::{CKKSAllOpsTmpBytes, CKKSBootstrappingOps};
use poulpy_ckks::layouts::{
    BootstrappingContext, BootstrappingKeySet, BootstrappingKeysPrepared, BootstrappingPipeline, CKKSModuleAlloc,
};
use poulpy_ckks::presets::bootstrapping::{all, BootstrappingPreset};
use poulpy_ckks::{CKKSLayout, CKKSMeta, SetCKKSInfos, SlotsKind};

use poulpy_core::layouts::{
    GLWEAutomorphismKeyPreparedFactory, GLWELayout, GLWESecretPrepared, GLWESecretPreparedFactory, GLWESecretSampling,
    GLWESwitchingKeyPreparedFactory, GLWETensorKeyPreparedFactory, ModuleCoreAlloc, Rank,
};

use poulpy_hal::api::{ScratchOwnedAlloc, ScratchOwnedBorrow};
use poulpy_hal::layouts::{Backend, Module, ScratchOwned};
use poulpy_hal::source::Source;

use std::cell::RefCell;

use crate::envelope::backend::BE;
use crate::fherma::Point;

pub type Ct = poulpy_ckks::layouts::CKKSCiphertextOwned<BE>;

/// The specification: the circuit. Everything else — sizes, widths, key
/// layout, hamming weights — comes with the preset the point selects.
pub const PIPELINE: BootstrappingPipeline = BootstrappingPipeline::S2CFirst;

/// The Poulpy preset for a point: the one with this pipeline and these sizes.
/// A point Poulpy ships no preset for is not a point of this specification.
///
/// The point is the signature's (`fherma::Point`, generated): `N`, `log_delta`,
/// `output_k` and `key_seed`, as the platform writes them in `manifest.json`.
pub fn preset_for(point: &Point) -> Result<BootstrappingPreset, String> {
    let presets = all().map_err(|e| format!("poulpy presets: {e}"))?;
    presets
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
        })
}

/// The Poulpy release the harness is written against (pinned in Cargo.toml).
pub const POULPY_VERSION: &str = "0.8.3";

/// The context: everything the envelope makes from the point, and what the
/// author's `init` is handed. Public material — the module, the compiled
/// bootstrapping context, the prepared keys — and, for the envelope's own use,
/// the secret and a scratch arena.
pub struct Context {
    pub preset: BootstrappingPreset,
    pub module: Module<BE>,
    pub context: BootstrappingContext<BE, f64>,
    pub keys: BootstrappingKeysPrepared<<BE as Backend>::OwnedBuf, BE>,
    /// The working memory a full bootstrap needs: an upper bound the author's
    /// `init` can size its own arena by.
    pub scratch_bytes: usize,
    /// The envelope's arena, for `generate` and `check`; `run` uses the author's.
    pub(crate) scratch: RefCell<ScratchOwned<BE>>,
    /// The secret `generate` encrypts with. Derivable from the point's
    /// `key_seed` by anyone; correctness is byte equality, so it needs no guarding.
    pub(crate) sk: GLWESecretPrepared<<BE as Backend>::OwnedBuf, BE>,
    pub(crate) input_layout: CKKSLayout,
}

impl Context {
    /// keygen from the point's key-seed. Once per benchmark point.
    pub fn setup(point: &Point) -> Self {
        let preset = preset_for(point).unwrap_or_else(|e| panic!("{e}"));
        let key_seed = point.key_seed;
        let plan = preset.plan();
        let n = preset.n();
        let base2k = preset.base2k();
        let input_layout = preset.input_layout();
        let bootstrap_layout = preset.bootstrap_layout();
        let keys_layout = *preset.keys_layout();
        let module = Module::<BE>::new(n as u64);

        // Scratch: sized for compile and the common ops, then grown to what the
        // full bootstrap needs.
        let scratch_size = {
            let mut ct = module.ckks_ciphertext_alloc_from_glwe_infos(&bootstrap_layout);
            ct.set_meta(bootstrap_layout.meta);
            module.ckks_all_ops_with_atk_tmp_bytes(
                &ct,
                &keys_layout.tensor_key,
                &keys_layout.automorphism_key,
                &ckks_spec(
                    n,
                    base2k,
                    plan.eval_mod().coeffs_meta.log_delta(),
                    plan.eval_mod().coeffs_meta.log_budget(),
                ),
            )
        };
        let mut scratch = ScratchOwned::<BE>::alloc(scratch_size);
        let context = BootstrappingContext::<BE, f64>::compile(&module, base2k.into(), plan, &mut scratch.borrow())
            .expect("compile the preset's bootstrapping plan");
        let boot_scratch = module.ckks_bootstrap_tmp_bytes(&bootstrap_layout, &input_layout, &context, &keys_layout);
        let scratch_bytes = scratch_size.max(boot_scratch);
        if boot_scratch > scratch_size {
            scratch = ScratchOwned::<BE>::alloc(boot_scratch);
        }

        // Dense application secret at the preset's Hamming weight.
        let mut source_sk = Source::new(seed32(key_seed, "sk"));
        let mut sk_raw = module.glwe_secret_alloc_from_infos(&bootstrap_layout.glwe_layout);
        module.glwe_secret_fill_ternary_hw(&mut sk_raw, preset.dense_secret_hamming_weight(), &mut source_sk);
        let mut sk = module.glwe_secret_prepared_alloc_from_infos(&bootstrap_layout.glwe_layout);
        module.glwe_secret_prepare(&mut sk, &sk_raw);

        // Bootstrapping keys: rotation, tensor, encapsulation. Generated as
        // Poulpy's preset driver does, then prepared one key at a time, each
        // unprepared key dropped as its prepared form is made. Poulpy's own
        // `prepare` borrows the whole set and so holds both forms at once —
        // at this point the keys are some 18 GB, and twice that is more than
        // the machines this runs on have. The keys themselves are the same.
        let mut source_xs = Source::new(seed32(key_seed, "xs"));
        let mut source_xa = Source::new(seed32(key_seed, "xa"));
        let mut source_xe = Source::new(seed32(key_seed, "xe"));
        let BootstrappingKeySet {
            rotation_keys,
            tensor_key,
            encapsulation_keys,
        } = context
            .generate_keys(
                &module,
                &sk_raw,
                &keys_layout,
                &mut source_xs,
                &mut source_xe,
                &mut source_xa,
                &mut scratch.borrow(),
            )
            .expect("generate the bootstrapping keys");
        let keys = {
            let mut rotation = std::collections::HashMap::with_capacity(rotation_keys.len());
            for (galois, key) in rotation_keys {
                let mut prepared = module.glwe_automorphism_key_prepared_alloc_from_infos(&key);
                module.glwe_automorphism_key_prepare(&mut prepared, &key, &mut scratch.borrow());
                rotation.insert(galois, prepared);
                drop(key);
            }
            let tensor = {
                let mut prepared = module.alloc_tensor_key_prepared_from_infos(&tensor_key);
                module.prepare_tensor_key(&mut prepared, &tensor_key, &mut scratch.borrow());
                drop(tensor_key);
                prepared
            };
            let encapsulation = encapsulation_keys.map(|(dense_to_sparse, sparse_to_dense)| {
                let mut d2s = module.glwe_switching_key_prepared_alloc_from_infos(&dense_to_sparse);
                module.glwe_switching_key_prepare(&mut d2s, &dense_to_sparse, &mut scratch.borrow());
                drop(dense_to_sparse);
                let mut s2d = module.glwe_switching_key_prepared_alloc_from_infos(&sparse_to_dense);
                module.glwe_switching_key_prepare(&mut s2d, &sparse_to_dense, &mut scratch.borrow());
                drop(sparse_to_dense);
                (d2s, s2d)
            });
            BootstrappingKeysPrepared {
                rotation_keys: rotation,
                tensor_key: tensor,
                encapsulation_keys: encapsulation,
            }
        };

        Context {
            preset,
            module,
            context,
            keys,
            scratch_bytes,
            scratch: RefCell::new(scratch),
            sk,
            input_layout,
        }
    }
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
        meta: CKKSMeta {
            log_sparsity: 0,
            log_delta,
            slots: SlotsKind::Complex,
        },
    }
}
