// Merkle tree utilities for Fantasma circuits
// Used for credential validity checking (inclusion/exclusion proofs)

use super::hash::hash_pair;

/// Verify a Merkle inclusion proof
/// Returns true if the leaf is included in the tree with the given root
pub fn verify_merkle_proof(
    leaf: felt252,
    proof: Span<felt252>,
    indices: Span<bool>, // false = left, true = right
    root: felt252
) -> bool {
    assert(proof.len() == indices.len(), 'proof and indices length mismatch');

    let mut current = leaf;
    let mut i: usize = 0;

    loop {
        if i >= proof.len() {
            break;
        }

        let sibling = *proof.at(i);
        let is_right = *indices.at(i);

        current = if is_right {
            hash_pair(sibling, current)
        } else {
            hash_pair(current, sibling)
        };

        i += 1;
    };

    current == root
}

/// Compute Merkle root from leaf and proof
pub fn compute_merkle_root(
    leaf: felt252,
    proof: Span<felt252>,
    indices: Span<bool>
) -> felt252 {
    assert(proof.len() == indices.len(), 'proof and indices length mismatch');

    let mut current = leaf;
    let mut i: usize = 0;

    loop {
        if i >= proof.len() {
            break;
        }

        let sibling = *proof.at(i);
        let is_right = *indices.at(i);

        current = if is_right {
            hash_pair(sibling, current)
        } else {
            hash_pair(current, sibling)
        };

        i += 1;
    };

    current
}
