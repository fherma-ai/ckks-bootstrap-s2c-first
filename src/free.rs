//! FREE — your teardown. NOT measured. Rust drops the state on its own; a
//! submission holding a device would release it here.

use crate::init::State;

pub fn free(state: State<'_>) {
    drop(state);
}
