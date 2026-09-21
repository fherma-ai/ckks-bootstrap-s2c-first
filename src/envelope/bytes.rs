//! The canonical bytes of a ciphertext: what a submission must reproduce.
//!
//! Correctness is `digest(submission output) == digest(reference output)`, and
//! the digest is over these bytes — the layout header and exactly the limbs
//! that carry the ciphertext's `k` bits, column by column, little-endian i64 —
//! so it does not depend on how big the buffer was allocated or what an
//! earlier computation left beyond `k`. Poulpy's exact NTT backends produce
//! the same limbs for the same seeds, so the reference's digest is the
//! expected answer for all of them. The digest itself is the loop's.

use poulpy_ckks::CKKSInfos;
use poulpy_core::layouts::{GLWEInfos, LWEInfos};
use poulpy_hal::layouts::ZnxView;

use super::keys::Ct;

const MAGIC: &[u8] = b"fherma/ckks-ct/v1";

/// The bytes of `ct` the digest is over — what `out/NNNNNN/<result>.bin` holds.
pub fn bytes(ct: &Ct) -> Vec<u8> {
    let n = ct.n().as_usize();
    let cols = ct.rank().as_usize() + 1;
    let size = ct.size(); // limbs holding the current `k` bits
    let data = ct.data();
    assert!(
        cols == data.cols() && size <= data.size() && n == data.n(),
        "ciphertext storage disagrees with its layout"
    );

    let mut out = Vec::with_capacity(MAGIC.len() + 6 * 8 + cols * size * n * 8);
    out.extend_from_slice(MAGIC);
    for v in [
        n as u64,
        cols as u64,
        ct.base2k().as_usize() as u64,
        ct.k().as_usize() as u64,
        ct.log_delta() as u64,
        slots_tag(ct),
    ] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for col in 0..cols {
        for limb in 0..size {
            for &c in data.at(col, limb) {
                out.extend_from_slice(&c.to_le_bytes());
            }
        }
    }
    out
}

fn slots_tag(ct: &Ct) -> u64 {
    match ct.slots() {
        poulpy_ckks::SlotsKind::Complex => 0,
        poulpy_ckks::SlotsKind::Real => 1,
    }
}
