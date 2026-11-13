//! GENERATE — one test case from its seed. NOT measured.
//!
//! The bundle's `generate`, inside the solution because it needs the secret:
//! the message and its encryption mask and error are all derived from the
//! case's seed, so a case is its seed. The client encrypts it on the host,
//! and the case stays there: a submission moves it to its backend itself.
//! The specification's file, laid over every submission.

use poulpy_ckks::api::{CKKSEncodingHostOps, CKKSEncryptOps};
use poulpy_ckks::layouts::{CKKSCiphertextAlloc, CKKSPlaintextAlloc};
use poulpy_ckks::{GLWEPlaintextMeta, SetCKKSInfos, SlotsKind};
use poulpy_core::layouts::LWEInfos;
use poulpy_hal::api::ScratchOwnedBorrow;
use poulpy_hal::source::Source;

use crate::fherma::Inputs;

use super::keys::{seed32, Context, HostCt};

/// One test case: the input ciphertext on the host, and the message it
/// encrypts — kept beside it so the output can be measured against it
/// (`check`).
pub struct Case {
    pub ct: HostCt,
    pub re: Vec<f64>,
    pub im: Vec<f64>,
}

/// One test case from its input — the signature's `Inputs`, one seed: the
/// message, encrypted at the preset's input layout. Message, encryption mask
/// and error all come from the seed.
pub fn generate(state: &Context, input: &Inputs) -> Case {
    let seed = input.case_seed;
    let preset = &state.preset;
    let (re, im) = sample_unit_disc(seed, preset.n() / 2);
    let client = &state.client;
    let layout = state.input_layout;

    let mut pt = client.ckks_plaintext_alloc_from_slots(preset.n() / 2, preset.base2k().into(), layout.k());
    pt.set_meta(GLWEPlaintextMeta {
        slots: SlotsKind::Complex,
        ..layout.meta
    });
    let mut arena = state.client_scratch.borrow_mut();
    client
        .ckks_encode_slots_host_into(&mut pt, &re, &im, &mut arena.borrow())
        .expect("encode the case message");

    let mut host = client.ckks_ciphertext_alloc_from_glwe_infos(&layout);
    let mut xa = Source::new(seed32(seed, "input-xa"));
    let mut xe = Source::new(seed32(seed, "input-xe"));
    client
        .ckks_encrypt_sk(&mut host, &pt, &state.sk, &mut xe, &mut xa, &mut arena.borrow())
        .expect("encrypt the case input");

    Case { ct: host, re, im }
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
