//! Claim types for Fantasma
//!
//! Claims are the assertions that can be proven via zero-knowledge proofs.
//! Each claim type corresponds to a specific Cairo circuit.

use serde::{Deserialize, Serialize};

/// KYC verification level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KycLevel {
    /// Basic identity verification
    Basic = 1,
    /// Enhanced due diligence
    Enhanced = 2,
    /// Accredited investor status
    Accredited = 3,
}

impl KycLevel {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(KycLevel::Basic),
            2 => Some(KycLevel::Enhanced),
            3 => Some(KycLevel::Accredited),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KycLevel::Basic => "basic",
            KycLevel::Enhanced => "enhanced",
            KycLevel::Accredited => "accredited",
        }
    }
}

/// Types of claims that can be proven via ZK circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimType {
    /// Prove age >= threshold without revealing birthdate
    AgeAtLeast {
        /// Minimum age required (e.g., 18, 21)
        threshold: u8,
    },

    /// Prove holding a credential of a specific type
    HoldsCredential {
        /// The credential type to prove (e.g., "degree", "license")
        credential_type: String,
        /// Optional: specific institution/issuer
        issuer: Option<String>,
    },

    /// Prove KYC status without revealing personal data
    KycStatus {
        /// KYC provider (or "*" for any)
        provider: String,
        /// Minimum KYC level required
        level: KycLevel,
        /// Maximum age of KYC verification in seconds
        max_age_seconds: Option<u64>,
    },

    /// Prove membership in a set (via Merkle inclusion)
    SetMembership {
        /// Identifier for the membership set
        set_id: String,
    },
}

impl ClaimType {
    /// Get the circuit identifier for this claim type
    pub fn circuit_id(&self) -> &'static str {
        match self {
            ClaimType::AgeAtLeast { .. } => "age_verification_v1",
            ClaimType::HoldsCredential { .. } => "credential_verification_v1",
            ClaimType::KycStatus { .. } => "kyc_verification_v1",
            ClaimType::SetMembership { .. } => "set_membership_v1",
        }
    }

    /// Parse from OIDC scope string
    pub fn from_scope(scope: &str) -> Option<Self> {
        if scope.starts_with("zk:age:") {
            let threshold_str = scope.strip_prefix("zk:age:")?.trim_end_matches('+');
            let threshold: u8 = threshold_str.parse().ok()?;
            Some(ClaimType::AgeAtLeast { threshold })
        } else if scope.starts_with("zk:credential:") {
            let credential_type = scope.strip_prefix("zk:credential:")?.to_string();
            Some(ClaimType::HoldsCredential {
                credential_type,
                issuer: None,
            })
        } else if scope == "zk:credential" {
            Some(ClaimType::HoldsCredential {
                credential_type: "*".to_string(),
                issuer: None,
            })
        } else if scope.starts_with("zk:kyc:") {
            let level_str = scope.strip_prefix("zk:kyc:")?;
            let level = match level_str {
                "basic" => KycLevel::Basic,
                "enhanced" => KycLevel::Enhanced,
                "accredited" => KycLevel::Accredited,
                _ => return None,
            };
            Some(ClaimType::KycStatus {
                provider: "*".to_string(),
                level,
                max_age_seconds: None,
            })
        } else {
            None
        }
    }

    /// Convert to OIDC scope string
    pub fn to_scope(&self) -> String {
        match self {
            ClaimType::AgeAtLeast { threshold } => format!("zk:age:{}+", threshold),
            ClaimType::HoldsCredential {
                credential_type, ..
            } => {
                if credential_type == "*" {
                    "zk:credential".to_string()
                } else {
                    format!("zk:credential:{}", credential_type)
                }
            }
            ClaimType::KycStatus { level, .. } => format!("zk:kyc:{}", level.as_str()),
            ClaimType::SetMembership { set_id } => format!("zk:set:{}", set_id),
        }
    }
}

/// A request for a specific claim proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// The type of claim being requested
    pub claim_type: ClaimType,

    /// Whether this claim is required (vs optional)
    pub required: bool,

    /// Human-readable reason for requesting this claim
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_parsing() {
        assert!(matches!(
            ClaimType::from_scope("zk:age:18+"),
            Some(ClaimType::AgeAtLeast { threshold: 18 })
        ));

        assert!(matches!(
            ClaimType::from_scope("zk:age:21+"),
            Some(ClaimType::AgeAtLeast { threshold: 21 })
        ));

        assert!(matches!(
            ClaimType::from_scope("zk:kyc:basic"),
            Some(ClaimType::KycStatus {
                level: KycLevel::Basic,
                ..
            })
        ));

        assert!(ClaimType::from_scope("invalid").is_none());
    }

    #[test]
    fn test_kyc_level_ordering() {
        assert!(KycLevel::Basic < KycLevel::Enhanced);
        assert!(KycLevel::Enhanced < KycLevel::Accredited);
    }
}
