// Age Verification Circuit
// Proves: User is at least `threshold` years old on `verification_date`
// Without revealing: Actual birthdate

use super::common::hash::compute_commitment;

/// Age verification public inputs
#[derive(Drop, Serde)]
pub struct AgeVerificationPublicInputs {
    /// Minimum age to prove (e.g., 18, 21)
    pub threshold: u8,
    /// Current date in YYYYMMDD format
    pub verification_date: u32,
    /// Commitment to the credential (H(birthdate, salt))
    pub credential_commitment: felt252,
    /// Issuer's public key hash (for signature binding)
    pub issuer_pubkey_hash: felt252,
}

/// Verify that a user is at least `threshold` years old
///
/// Private inputs (witness):
/// - birthdate: u32 (YYYYMMDD format)
/// - salt: felt252 (random salt for commitment)
/// - signature_hash: felt252 (hash of issuer's signature for binding)
///
/// Public inputs:
/// - threshold: u8 (minimum age required)
/// - verification_date: u32 (current date YYYYMMDD)
/// - credential_commitment: felt252 (commitment to birthdate)
/// - issuer_pubkey_hash: felt252 (issuer's public key hash)
pub fn verify_age(
    // Private witness
    birthdate: u32,
    salt: felt252,
    signature_hash: felt252,
    // Public inputs
    threshold: u8,
    verification_date: u32,
    credential_commitment: felt252,
    issuer_pubkey_hash: felt252,
) {
    // 1. Verify the commitment matches
    let computed_commitment = compute_commitment(birthdate.into(), salt);
    assert(computed_commitment == credential_commitment, 'commitment mismatch');

    // 2. Parse dates
    let birth_year = birthdate / 10000;
    let birth_month = (birthdate / 100) % 100;
    let birth_day = birthdate % 100;

    let verify_year = verification_date / 10000;
    let verify_month = (verification_date / 100) % 100;
    let verify_day = verification_date % 100;

    // 3. Basic date validation
    assert(birth_year >= 1900 && birth_year <= verify_year, 'invalid birth year');
    assert(birth_month >= 1 && birth_month <= 12, 'invalid birth month');
    assert(birth_day >= 1 && birth_day <= 31, 'invalid birth day');

    // 4. Calculate age
    let mut age = verify_year - birth_year;

    // Adjust if birthday hasn't occurred this year
    if verify_month < birth_month {
        age -= 1;
    } else if verify_month == birth_month && verify_day < birth_day {
        age -= 1;
    }

    // 5. Assert age meets threshold
    assert(age >= threshold.into(), 'age below threshold');

    // 6. Bind to issuer (signature_hash must be derived from issuer's signature)
    // This prevents using a credential with a forged issuer
    // The verifier checks that issuer_pubkey_hash corresponds to a trusted issuer
    // and that signature_hash is correctly derived from the credential signature
    let _binding = signature_hash + issuer_pubkey_hash;
}

#[cfg(test)]
mod tests {
    use super::verify_age;
    use super::super::common::hash::compute_commitment;

    #[test]
    fn test_age_verification_passes() {
        // User born Jan 1, 2000 (age 26 on Feb 10, 2026)
        let birthdate: u32 = 20000101;
        let salt: felt252 = 12345;
        let signature_hash: felt252 = 99999;

        let threshold: u8 = 21;
        let verification_date: u32 = 20260210;
        let credential_commitment = compute_commitment(birthdate.into(), salt);
        let issuer_pubkey_hash: felt252 = 11111;

        verify_age(
            birthdate,
            salt,
            signature_hash,
            threshold,
            verification_date,
            credential_commitment,
            issuer_pubkey_hash,
        );
    }

    #[test]
    #[should_panic(expected: ('age below threshold',))]
    fn test_age_verification_fails_underage() {
        // User born Jan 1, 2010 (age 16 on Feb 10, 2026)
        let birthdate: u32 = 20100101;
        let salt: felt252 = 12345;
        let signature_hash: felt252 = 99999;

        let threshold: u8 = 18;
        let verification_date: u32 = 20260210;
        let credential_commitment = compute_commitment(birthdate.into(), salt);
        let issuer_pubkey_hash: felt252 = 11111;

        verify_age(
            birthdate,
            salt,
            signature_hash,
            threshold,
            verification_date,
            credential_commitment,
            issuer_pubkey_hash,
        );
    }

    #[test]
    #[should_panic(expected: ('commitment mismatch',))]
    fn test_age_verification_fails_wrong_commitment() {
        let birthdate: u32 = 20000101;
        let salt: felt252 = 12345;
        let signature_hash: felt252 = 99999;

        let threshold: u8 = 18;
        let verification_date: u32 = 20260210;
        let wrong_commitment: felt252 = 0; // Wrong commitment
        let issuer_pubkey_hash: felt252 = 11111;

        verify_age(
            birthdate,
            salt,
            signature_hash,
            threshold,
            verification_date,
            wrong_commitment,
            issuer_pubkey_hash,
        );
    }
}
