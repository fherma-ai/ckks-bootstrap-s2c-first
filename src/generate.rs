//! GENERATE — one test case from its seed. NOT measured.
//!
//! The bundle's `generate`, inside the solution because it needs the secret:
//! the message and its encryption mask and error are all derived from the
//! case's seed, so a case is its seed. The platform owns this file.

use poulpy_ckks::api::{CKKSEncodingHostOps, CKKSEncryptOps};
use poulpy_ckks::layouts::CKKSModuleAlloc;
use poulpy_ckks::{CKKSInfos, SetCKKSInfos};
use poulpy_core::layouts::LWEInfos;
use poulpy_core::EncryptionLayout;
use poulpy_hal::api::ScratchOwnedBorrow;
use poulpy_hal::source::Source;

use crate::fherma::Inputs;
use crate::init::{seed32, Ct, State};

/// One test case: the input ciphertext, and the message it encrypts — kept
/// beside it so the output can be measured against it (`check`).
pub struct Case {
    pub input: Ct,
    pub re: Vec<f64>,
    pub im: Vec<f64>,
}

/// One test case from its input — the signature's `Inputs`, one seed: the
/// message, encrypted at the preset's input layout. Message, encryption mask
/// and error all come from the seed.
pub fn generate(state: &mut State, input: &Inputs) -> Case {
    let seed = input.case_seed;
    let (re, im) = sample_unit_disc(seed, state.preset.n() / 2);

    let mut pt = state
        .module
        .ckks_pt_vec_alloc(state.preset.base2k().into(), state.input_layout.k());
    pt.set_meta(state.input_layout.meta());
    state
        .module
        .ckks_encode_reim_into(&mut pt, &re, &im, &mut state.scratch.borrow())
        .expect("encode the case message");

    let enc = EncryptionLayout::new_from_default_sigma(state.input_layout.glwe_layout)
        .expect("encryption layout for the input");
    let mut ct = state.module.ckks_ciphertext_alloc_from_glwe_infos(&state.input_layout);
    let mut xa = Source::new(seed32(seed, "input-xa"));
    let mut xe = Source::new(seed32(seed, "input-xe"));
    state
        .module
        .ckks_encrypt_sk(
            &mut ct,
            &pt,
            &state.sk,
            &enc,
            &mut xe,
            &mut xa,
            &mut state.scratch.borrow(),
        )
        .expect("encrypt the case input");
    Case { input: ct, re, im }
}

/// `m` complex values uniform on the unit disc, from the case-seed: SplitMix64
/// over a per-case root, points drawn uniformly in the square and kept when
/// inside the disc. Only multiplication and comparison — no libm, so the same
/// seed gives the same f64 message bit-for-bit on any platform.
fn sample_unit_disc(seed: u64, m: usize) -> (Vec<f64>, Vec<f64>) {
    let mut state = u64::from_le_bytes(seed32(seed, "msg")[..8].try_into().unwrap());
    let mut next = || -> f64 {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 52) as f64 - 1.0 // in [-1, 1)
    };
    let (mut re, mut im) = (Vec::with_capacity(m), Vec::with_capacity(m));
    while re.len() < m {
        let (x, y) = (next(), next());
        if x * x + y * y < 1.0 {
            re.push(x);
            im.push(y);
        }
    }
    (re, im)
}
