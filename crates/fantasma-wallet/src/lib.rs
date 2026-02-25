//! Fantasma Wallet
//!
//! User credential storage and management.

use fantasma_core::credential::Credential;
use fantasma_core::FantasmaError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

/// Encrypted credential storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCredential {
    /// Credential ID
    pub id: String,

    /// Encrypted credential data
    pub encrypted_data: Vec<u8>,

    /// Nonce used for encryption
    pub nonce: [u8; 12],

    /// Schema ID
    pub schema: String,
}

/// User wallet containing credentials
pub struct Wallet {
    /// User's secret (for nullifier generation)
    user_secret: [u8; 32],

    /// Stored credentials (in-memory for now)
    credentials: HashMap<String, Credential>,
}

impl Wallet {
    /// Create a new wallet with a random secret
    pub fn new() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        Self {
            user_secret: secret,
            credentials: HashMap::new(),
        }
    }

    /// Create a wallet with a specific secret
    pub fn with_secret(secret: [u8; 32]) -> Self {
        Self {
            user_secret: secret,
            credentials: HashMap::new(),
        }
    }

    /// Get the user secret (for nullifier generation)
    pub fn user_secret(&self) -> &[u8; 32] {
        &self.user_secret
    }

    /// Import a credential into the wallet
    pub fn import_credential(&mut self, credential: Credential) -> Result<(), FantasmaError> {
        // Verify the credential is valid
        if credential.is_expired() {
            return Err(FantasmaError::CredentialExpired);
        }

        let id = credential.id.to_hex();
        self.credentials.insert(id, credential);
        Ok(())
    }

    /// Get a credential by ID
    pub fn get_credential(&self, id: &str) -> Option<&Credential> {
        self.credentials.get(id)
    }

    /// List all credentials
    pub fn list_credentials(&self) -> Vec<&Credential> {
        self.credentials.values().collect()
    }

    /// Find credentials matching a claim type
    pub fn find_credentials_for_claim(&self, claim: &fantasma_core::ClaimType) -> Vec<&Credential> {
        self.credentials
            .values()
            .filter(|c| credential_supports_claim(c, claim))
            .collect()
    }

    /// Remove a credential
    pub fn remove_credential(&mut self, id: &str) -> Option<Credential> {
        self.credentials.remove(id)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.user_secret.zeroize();
    }
}

/// Check if a credential can be used for a specific claim
fn credential_supports_claim(credential: &Credential, claim: &fantasma_core::ClaimType) -> bool {
    use fantasma_core::claim::ClaimType;
    use fantasma_core::credential::CredentialType;

    match claim {
        ClaimType::AgeAtLeast { .. } => {
            matches!(credential.credential_type, CredentialType::Identity { .. })
        }
        ClaimType::HoldsCredential {
            credential_type, ..
        } => {
            if credential_type == "*" {
                return true;
            }
            match &credential.credential_type {
                CredentialType::Degree { .. } => credential_type == "degree",
                CredentialType::License { .. } => credential_type == "license",
                CredentialType::Membership { .. } => credential_type == "membership",
                _ => false,
            }
        }
        ClaimType::KycStatus { level, .. } => {
            if let CredentialType::Kyc {
                level: cred_level, ..
            } = &credential.credential_type
            {
                cred_level >= level
            } else {
                false
            }
        }
        ClaimType::SetMembership { .. } => false, // Not yet implemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new();
        assert!(!wallet.user_secret().iter().all(|&b| b == 0));
    }
}
