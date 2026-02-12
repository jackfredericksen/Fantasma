// Hash utilities for Fantasma circuits
// Uses Poseidon hash which is STARK-friendly and post-quantum secure

use core::poseidon::PoseidonTrait;
use core::hash::HashStateTrait;

/// Hash two field elements using Poseidon
pub fn hash_pair(a: felt252, b: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    state = state.update(a);
    state = state.update(b);
    state.finalize()
}

/// Hash multiple field elements using Poseidon
pub fn hash_many(values: Span<felt252>) -> felt252 {
    let mut state = PoseidonTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= values.len() {
            break;
        }
        state = state.update(*values.at(i));
        i += 1;
    };
    state.finalize()
}

/// Compute a commitment: H(value, salt)
pub fn compute_commitment(value: felt252, salt: felt252) -> felt252 {
    hash_pair(value, salt)
}

/// Compute a commitment for multiple values: H(v1, v2, ..., salt)
pub fn compute_multi_commitment(values: Span<felt252>, salt: felt252) -> felt252 {
    let mut state = PoseidonTrait::new();
    let mut i: usize = 0;
    loop {
        if i >= values.len() {
            break;
        }
        state = state.update(*values.at(i));
        i += 1;
    };
    state = state.update(salt);
    state.finalize()
}
