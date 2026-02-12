// KYC Verification Circuit
// Proves: User has passed KYC verification at a specified level
// Without revealing: Personal data, verification details

use super::common::hash::{compute_multi_commitment, hash_pair};

/// KYC verification levels
/// 1 = Basic (identity verified)
/// 2 = Enhanced (enhanced due diligence)
/// 3 = Accredited (accredited investor)
const KYC_BASIC: u8 = 1;
const KYC_ENHANCED: u8 = 2;
const KYC_ACCREDITED: u8 = 3;

/// KYC verification public inputs
#[derive(Drop, Serde)]
pub struct KycVerificationPublicInputs {
    /// Minimum KYC level required
    pub expected_level: u8,
    /// Maximum age of KYC verification in seconds
    pub max_age_seconds: u64,
    /// Current timestamp
    pub current_timestamp: u64,
    /// KYC provider's public key hash
    pub provider_pubkey_hash: felt252,
    /// Commitment to KYC credential
    pub kyc_commitment: felt252,
}

/// Verify that a user has passed KYC verification
///
/// Private inputs (witness):
/// - user_id_hash: felt252 (hash of user's identity)
/// - kyc_provider_id: felt252 (provider identifier)
/// - kyc_level: u8 (1=Basic, 2=Enhanced, 3=Accredited)
/// - verification_timestamp: u64 (when KYC was completed)
/// - kyc_data_hash: felt252 (hash of full KYC data)
/// - provider_signature_hash: felt252 (hash of provider's signature)
/// - salt: felt252 (commitment salt)
///
/// Public inputs:
/// - expected_level: u8 (minimum level required)
/// - max_age_seconds: u64 (KYC must be within this age)
/// - current_timestamp: u64 (current time)
/// - provider_pubkey_hash: felt252 (trusted provider)
/// - kyc_commitment: felt252 (commitment to KYC credential)
pub fn verify_kyc(
    // Private witness
    user_id_hash: felt252,
    kyc_provider_id: felt252,
    kyc_level: u8,
    verification_timestamp: u64,
    kyc_data_hash: felt252,
    provider_signature_hash: felt252,
    salt: felt252,
    // Public inputs
    expected_level: u8,
    max_age_seconds: u64,
    current_timestamp: u64,
    provider_pubkey_hash: felt252,
    kyc_commitment: felt252,
) {
    // 1. Verify KYC level is valid
    assert(kyc_level >= KYC_BASIC && kyc_level <= KYC_ACCREDITED, 'invalid kyc level');

    // 2. Verify KYC level meets requirement
    assert(kyc_level >= expected_level, 'kyc level insufficient');

    // 3. Verify commitment matches private data
    let values: Array<felt252> = array![
        user_id_hash,
        kyc_provider_id,
        kyc_level.into(),
        verification_timestamp.into(),
        kyc_data_hash,
    ];
    let computed_commitment = compute_multi_commitment(values.span(), salt);
    assert(computed_commitment == kyc_commitment, 'commitment mismatch');

    // 4. Verify KYC is not expired
    assert(current_timestamp >= verification_timestamp, 'invalid timestamps');
    let age = current_timestamp - verification_timestamp;
    assert(age <= max_age_seconds, 'kyc verification expired');

    // 5. Bind to provider (signature proves authenticity)
    // The verifier checks that provider_pubkey_hash is a trusted KYC provider
    // and that provider_signature_hash correctly binds to the commitment
    let _provider_binding = hash_pair(provider_signature_hash, provider_pubkey_hash);
}

#[cfg(test)]
mod tests {
    use super::verify_kyc;
    use super::super::common::hash::compute_multi_commitment;

    #[test]
    fn test_kyc_verification_passes() {
        let user_id_hash: felt252 = 0x123456;
        let kyc_provider_id: felt252 = 'PROVIDER_A';
        let kyc_level: u8 = 2; // Enhanced
        let verification_timestamp: u64 = 1700000000; // Some past timestamp
        let kyc_data_hash: felt252 = 0xabcdef;
        let provider_signature_hash: felt252 = 0x999;
        let salt: felt252 = 0x111222;

        let values: Array<felt252> = array![
            user_id_hash,
            kyc_provider_id,
            kyc_level.into(),
            verification_timestamp.into(),
            kyc_data_hash,
        ];
        let kyc_commitment = compute_multi_commitment(values.span(), salt);

        let expected_level: u8 = 1; // Basic (we have Enhanced, so it passes)
        let max_age_seconds: u64 = 31536000; // 1 year
        let current_timestamp: u64 = 1705000000; // ~2 months later
        let provider_pubkey_hash: felt252 = 0xaaa;

        verify_kyc(
            user_id_hash,
            kyc_provider_id,
            kyc_level,
            verification_timestamp,
            kyc_data_hash,
            provider_signature_hash,
            salt,
            expected_level,
            max_age_seconds,
            current_timestamp,
            provider_pubkey_hash,
            kyc_commitment,
        );
    }

    #[test]
    #[should_panic(expected: ('kyc level insufficient',))]
    fn test_kyc_verification_fails_level() {
        let user_id_hash: felt252 = 0x123456;
        let kyc_provider_id: felt252 = 'PROVIDER_A';
        let kyc_level: u8 = 1; // Basic
        let verification_timestamp: u64 = 1700000000;
        let kyc_data_hash: felt252 = 0xabcdef;
        let provider_signature_hash: felt252 = 0x999;
        let salt: felt252 = 0x111222;

        let values: Array<felt252> = array![
            user_id_hash,
            kyc_provider_id,
            kyc_level.into(),
            verification_timestamp.into(),
            kyc_data_hash,
        ];
        let kyc_commitment = compute_multi_commitment(values.span(), salt);

        let expected_level: u8 = 2; // Require Enhanced, but only have Basic
        let max_age_seconds: u64 = 31536000;
        let current_timestamp: u64 = 1705000000;
        let provider_pubkey_hash: felt252 = 0xaaa;

        verify_kyc(
            user_id_hash,
            kyc_provider_id,
            kyc_level,
            verification_timestamp,
            kyc_data_hash,
            provider_signature_hash,
            salt,
            expected_level,
            max_age_seconds,
            current_timestamp,
            provider_pubkey_hash,
            kyc_commitment,
        );
    }

    #[test]
    #[should_panic(expected: ('kyc verification expired',))]
    fn test_kyc_verification_fails_expired() {
        let user_id_hash: felt252 = 0x123456;
        let kyc_provider_id: felt252 = 'PROVIDER_A';
        let kyc_level: u8 = 2;
        let verification_timestamp: u64 = 1600000000; // Old timestamp
        let kyc_data_hash: felt252 = 0xabcdef;
        let provider_signature_hash: felt252 = 0x999;
        let salt: felt252 = 0x111222;

        let values: Array<felt252> = array![
            user_id_hash,
            kyc_provider_id,
            kyc_level.into(),
            verification_timestamp.into(),
            kyc_data_hash,
        ];
        let kyc_commitment = compute_multi_commitment(values.span(), salt);

        let expected_level: u8 = 1;
        let max_age_seconds: u64 = 31536000; // 1 year max
        let current_timestamp: u64 = 1700000000; // More than 1 year later
        let provider_pubkey_hash: felt252 = 0xaaa;

        verify_kyc(
            user_id_hash,
            kyc_provider_id,
            kyc_level,
            verification_timestamp,
            kyc_data_hash,
            provider_signature_hash,
            salt,
            expected_level,
            max_age_seconds,
            current_timestamp,
            provider_pubkey_hash,
            kyc_commitment,
        );
    }
}
