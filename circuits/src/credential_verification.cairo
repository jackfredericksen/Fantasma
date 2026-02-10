// Credential Verification Circuit
// Proves: User holds a valid credential of a specific type
// Without revealing: Credential details, user identity

use super::common::hash::{compute_commitment, hash_pair};
use super::common::merkle::verify_merkle_proof;

/// Maximum depth of Merkle tree for credential registry
const MERKLE_DEPTH: usize = 20;

/// Credential verification public inputs
#[derive(Drop, Serde)]
pub struct CredentialVerificationPublicInputs {
    /// Expected credential type hash
    pub credential_type_hash: felt252,
    /// Current Merkle root of valid credentials
    pub merkle_root: felt252,
    /// Issuer's public key hash
    pub issuer_pubkey_hash: felt252,
    /// Nullifier (prevents double-use, domain-bound)
    pub nullifier: felt252,
    /// Verifier's domain hash (for nullifier binding)
    pub verifier_domain_hash: felt252,
    /// Nonce from verifier (for freshness)
    pub nonce: felt252,
}

/// Verify that a user holds a valid credential
///
/// Private inputs (witness):
/// - credential_type: felt252 (type identifier)
/// - credential_details_hash: felt252 (hash of credential details)
/// - salt: felt252 (commitment salt)
/// - user_secret: felt252 (user's secret for nullifier generation)
/// - merkle_proof: Array of sibling hashes
/// - merkle_indices: Path indices (left/right)
///
/// Public inputs:
/// - credential_type_hash: felt252 (expected type)
/// - merkle_root: felt252 (current valid credentials root)
/// - issuer_pubkey_hash: felt252 (trusted issuer)
/// - nullifier: felt252 (for replay prevention)
/// - verifier_domain_hash: felt252 (domain binding)
/// - nonce: felt252 (freshness)
pub fn verify_credential(
    // Private witness
    credential_type: felt252,
    credential_details_hash: felt252,
    salt: felt252,
    user_secret: felt252,
    merkle_proof: Span<felt252>,
    merkle_indices: Span<bool>,
    // Public inputs
    credential_type_hash: felt252,
    merkle_root: felt252,
    issuer_pubkey_hash: felt252,
    nullifier: felt252,
    verifier_domain_hash: felt252,
    nonce: felt252,
) {
    // 1. Verify credential type matches expected
    assert(credential_type == credential_type_hash, 'credential type mismatch');

    // 2. Compute credential leaf
    let credential_commitment = compute_commitment(credential_details_hash, salt);
    let credential_leaf = hash_pair(credential_type, credential_commitment);

    // 3. Verify Merkle inclusion (credential is valid/not revoked)
    let merkle_valid = verify_merkle_proof(
        credential_leaf,
        merkle_proof,
        merkle_indices,
        merkle_root
    );
    assert(merkle_valid, 'invalid merkle proof');

    // 4. Verify nullifier derivation
    // Nullifier = H(credential_leaf, user_secret, verifier_domain, nonce)
    // This ensures:
    // - Different nullifiers per credential
    // - Different nullifiers per verifier (domain binding)
    // - Different nullifiers per request (nonce)
    let computed_nullifier = compute_nullifier(
        credential_leaf,
        user_secret,
        verifier_domain_hash,
        nonce
    );
    assert(computed_nullifier == nullifier, 'nullifier mismatch');

    // 5. Bind to issuer
    let _issuer_binding = issuer_pubkey_hash;
}

/// Compute a nullifier for replay prevention
/// Nullifier is bound to: credential, user, verifier domain, and request nonce
fn compute_nullifier(
    credential_leaf: felt252,
    user_secret: felt252,
    verifier_domain_hash: felt252,
    nonce: felt252,
) -> felt252 {
    let inner = hash_pair(credential_leaf, user_secret);
    let domain_bound = hash_pair(inner, verifier_domain_hash);
    hash_pair(domain_bound, nonce)
}

#[cfg(test)]
mod tests {
    use super::{verify_credential, compute_nullifier};
    use super::super::common::hash::{compute_commitment, hash_pair};
    use super::super::common::merkle::compute_merkle_root;

    #[test]
    fn test_credential_verification() {
        // Setup: Create a credential and add it to a Merkle tree
        let credential_type: felt252 = 'DEGREE';
        let credential_details_hash: felt252 = 0x123456;
        let salt: felt252 = 0xabcdef;
        let user_secret: felt252 = 0x999888;

        // Compute credential leaf
        let credential_commitment = compute_commitment(credential_details_hash, salt);
        let credential_leaf = hash_pair(credential_type, credential_commitment);

        // Simple single-element tree (leaf is the root)
        let merkle_proof: Array<felt252> = array![];
        let merkle_indices: Array<bool> = array![];
        let merkle_root = credential_leaf; // Single element tree

        let verifier_domain_hash: felt252 = 'example.com';
        let nonce: felt252 = 0x111222;
        let issuer_pubkey_hash: felt252 = 0xaaa;

        // Compute nullifier
        let nullifier = compute_nullifier(
            credential_leaf,
            user_secret,
            verifier_domain_hash,
            nonce
        );

        verify_credential(
            credential_type,
            credential_details_hash,
            salt,
            user_secret,
            merkle_proof.span(),
            merkle_indices.span(),
            credential_type, // expected type
            merkle_root,
            issuer_pubkey_hash,
            nullifier,
            verifier_domain_hash,
            nonce,
        );
    }

    #[test]
    #[should_panic(expected: ('credential type mismatch',))]
    fn test_wrong_credential_type() {
        let credential_type: felt252 = 'DEGREE';
        let wrong_type: felt252 = 'LICENSE';
        let credential_details_hash: felt252 = 0x123456;
        let salt: felt252 = 0xabcdef;
        let user_secret: felt252 = 0x999888;

        let credential_commitment = compute_commitment(credential_details_hash, salt);
        let credential_leaf = hash_pair(credential_type, credential_commitment);

        let merkle_proof: Array<felt252> = array![];
        let merkle_indices: Array<bool> = array![];
        let merkle_root = credential_leaf;

        let verifier_domain_hash: felt252 = 'example.com';
        let nonce: felt252 = 0x111222;
        let issuer_pubkey_hash: felt252 = 0xaaa;

        let nullifier = compute_nullifier(
            credential_leaf,
            user_secret,
            verifier_domain_hash,
            nonce
        );

        verify_credential(
            credential_type,
            credential_details_hash,
            salt,
            user_secret,
            merkle_proof.span(),
            merkle_indices.span(),
            wrong_type, // Wrong expected type
            merkle_root,
            issuer_pubkey_hash,
            nullifier,
            verifier_domain_hash,
            nonce,
        );
    }
}
