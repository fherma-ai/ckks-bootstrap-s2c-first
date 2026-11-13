//! FREE — your teardown. NOT measured. Rust drops the state on its own; a
//! submission holding a device would release it here.

use crate::init::State;

pub fn free(state: State<'_>) {
    // Whether the recording was still a graph after every replay: a replay
    // that the runtime refused falls back to calling the closure.
    #[cfg(any(feature = "cuda", feature = "wgpu"))]
    crate::init::report("after the cases", &state.replay);
    drop(state);
}
