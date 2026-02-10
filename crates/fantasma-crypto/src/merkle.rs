//! Merkle tree implementation for credential registry
//!
//! Uses a sparse Merkle tree for efficient inclusion/exclusion proofs.

use crate::hash::poseidon_hash_pair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum depth of the Merkle tree
pub const MERKLE_DEPTH: usize = 20;

/// A Merkle proof for inclusion verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Sibling hashes from leaf to root
    pub siblings: Vec<[u8; 32]>,
    /// Path indices (false = left, true = right)
    pub indices: Vec<bool>,
    /// The leaf being proven
    pub leaf: [u8; 32],
}

impl MerkleProof {
    /// Verify this proof against a root
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        let computed_root = self.compute_root();
        &computed_root == root
    }

    /// Compute the root from this proof
    pub fn compute_root(&self) -> [u8; 32] {
        let mut current = self.leaf;

        for (sibling, is_right) in self.siblings.iter().zip(self.indices.iter()) {
            current = if *is_right {
                poseidon_hash_pair(sibling, &current)
            } else {
                poseidon_hash_pair(&current, sibling)
            };
        }

        current
    }

    /// Convert to format suitable for Cairo circuits
    pub fn to_circuit_format(&self) -> (Vec<[u8; 32]>, Vec<bool>) {
        (self.siblings.clone(), self.indices.clone())
    }
}

/// Sparse Merkle tree for credential registry
pub struct MerkleTree {
    /// Tree depth
    depth: usize,
    /// Non-empty nodes: (level, index) -> hash
    nodes: HashMap<(usize, u64), [u8; 32]>,
    /// Default (empty) hashes at each level
    default_hashes: Vec<[u8; 32]>,
    /// Number of leaves
    leaf_count: u64,
}

impl MerkleTree {
    /// Create a new empty Merkle tree
    pub fn new(depth: usize) -> Self {
        assert!(depth <= MERKLE_DEPTH, "Depth exceeds maximum");

        // Compute default hashes for empty nodes at each level
        let mut default_hashes = vec![[0u8; 32]; depth + 1];
        for i in 1..=depth {
            default_hashes[i] = poseidon_hash_pair(&default_hashes[i - 1], &default_hashes[i - 1]);
        }

        Self {
            depth,
            nodes: HashMap::new(),
            default_hashes,
            leaf_count: 0,
        }
    }

    /// Get the current root
    pub fn root(&self) -> [u8; 32] {
        self.get_node(self.depth, 0)
    }

    /// Insert a leaf at the next available position
    pub fn insert(&mut self, leaf: [u8; 32]) -> MerkleProof {
        let index = self.leaf_count;
        self.set_leaf(index, leaf);
        self.leaf_count += 1;
        self.prove(index).expect("Leaf was just inserted")
    }

    /// Insert a leaf at a specific index (for sparse tree)
    pub fn set_leaf(&mut self, index: u64, leaf: [u8; 32]) {
        self.nodes.insert((0, index), leaf);
        self.update_path(index);
    }

    /// Remove a leaf (set to default/empty)
    pub fn remove(&mut self, index: u64) {
        self.nodes.remove(&(0, index));
        self.update_path(index);
    }

    /// Get a node at (level, index), returning default hash if empty
    fn get_node(&self, level: usize, index: u64) -> [u8; 32] {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.default_hashes[level])
    }

    /// Update the path from a leaf to the root
    fn update_path(&mut self, leaf_index: u64) {
        let mut current_index = leaf_index;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1;
            let parent_index = current_index / 2;

            let left = if current_index % 2 == 0 {
                self.get_node(level, current_index)
            } else {
                self.get_node(level, sibling_index)
            };

            let right = if current_index % 2 == 0 {
                self.get_node(level, sibling_index)
            } else {
                self.get_node(level, current_index)
            };

            let parent_hash = poseidon_hash_pair(&left, &right);

            if parent_hash == self.default_hashes[level + 1] {
                self.nodes.remove(&(level + 1, parent_index));
            } else {
                self.nodes.insert((level + 1, parent_index), parent_hash);
            }

            current_index = parent_index;
        }
    }

    /// Generate a proof for a leaf at the given index
    pub fn prove(&self, index: u64) -> Option<MerkleProof> {
        let leaf = self.get_node(0, index);

        let mut siblings = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);
        let mut current_index = index;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1;
            siblings.push(self.get_node(level, sibling_index));
            indices.push(current_index % 2 == 1);
            current_index /= 2;
        }

        Some(MerkleProof {
            siblings,
            indices,
            leaf,
        })
    }

    /// Check if a leaf exists at the given index
    pub fn contains(&self, index: u64) -> bool {
        self.nodes.contains_key(&(0, index))
    }

    /// Get the number of non-empty leaves
    pub fn len(&self) -> u64 {
        self.leaf_count
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new(MERKLE_DEPTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(10);
        let root = tree.root();
        assert_eq!(root, tree.default_hashes[10]);
    }

    #[test]
    fn test_insert_and_prove() {
        let mut tree = MerkleTree::new(10);
        let leaf = [1u8; 32];

        let proof = tree.insert(leaf);

        assert_eq!(proof.leaf, leaf);
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn test_multiple_inserts() {
        let mut tree = MerkleTree::new(10);

        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];

        tree.insert(leaf1);
        tree.insert(leaf2);
        let proof3 = tree.insert(leaf3);

        assert!(proof3.verify(&tree.root()));

        // Prove earlier leaves still work
        let proof1 = tree.prove(0).unwrap();
        assert!(proof1.verify(&tree.root()));
    }

    #[test]
    fn test_remove() {
        let mut tree = MerkleTree::new(10);
        let leaf = [1u8; 32];

        tree.insert(leaf);
        let root_with_leaf = tree.root();

        tree.remove(0);
        let root_after_remove = tree.root();

        // Root should change after removal
        assert_ne!(root_with_leaf, root_after_remove);

        // Root should be back to empty tree default
        let empty_tree = MerkleTree::new(10);
        assert_eq!(root_after_remove, empty_tree.root());
    }
}
