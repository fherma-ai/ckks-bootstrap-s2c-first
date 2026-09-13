// GENERATED from bootstrap/s2c@1.0.0. Do not edit — `--update` rewrites it.
//
// The types your answer is written against, derived from the signature: one
// field per value parameter, per argument, per result. A tensor is typed,
// because the signature already settled what its elements are.
//
// Fields are named as the signature names them (`N`, not `n`), and a harness
// may have no use for one of these types; neither is worth a warning.
#![allow(non_snake_case, dead_code)]

#[derive(Debug, Clone, Default)]
pub struct Tensor<T> {
    pub shape: Vec<i64>,
    pub data: Vec<T>,          // row-major
}

impl<T> Tensor<T> {
    pub fn count(&self) -> usize {
        self.shape.iter().product::<i64>() as usize
    }
}

#[derive(Debug, Clone, Default)]
pub struct Point {
    pub N: u32,   // u32
    pub log_delta: u32,   // u32
    pub output_k: u32,   // u32
    pub key_seed: u64,   // u64
}

#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub case_seed: u64,   // u64
}

#[derive(Debug, Clone, Default)]
pub struct Outputs {
    pub ct: Tensor<i64>,   // tensor<N x i64>
}
