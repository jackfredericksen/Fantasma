//! OIDC scope definitions for ZK claims

use fantasma_core::claim::{ClaimType, KycLevel};
use serde::{Deserialize, Serialize};

/// ZK-specific OIDC scope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkScope {
    /// Standard OpenID scope
    OpenId,

    /// Age verification scope
    Age { threshold: u8 },

    /// Credential verification scope
    Credential { credential_type: Option<String> },

    /// KYC verification scope
    Kyc { level: KycLevel },
}

impl ZkScope {
    /// Parse a scope string
    pub fn parse(scope: &str) -> Option<Self> {
        match scope {
            "openid" => Some(ZkScope::OpenId),
            s if s.starts_with("zk:age:") => {
                let threshold_str = s.strip_prefix("zk:age:")?.trim_end_matches('+');
                let threshold: u8 = threshold_str.parse().ok()?;
                Some(ZkScope::Age { threshold })
            }
            "zk:credential" => Some(ZkScope::Credential {
                credential_type: None,
            }),
            s if s.starts_with("zk:credential:") => {
                let cred_type = s.strip_prefix("zk:credential:")?;
                Some(ZkScope::Credential {
                    credential_type: Some(cred_type.to_string()),
                })
            }
            "zk:kyc:basic" => Some(ZkScope::Kyc {
                level: KycLevel::Basic,
            }),
            "zk:kyc:enhanced" => Some(ZkScope::Kyc {
                level: KycLevel::Enhanced,
            }),
            "zk:kyc:accredited" => Some(ZkScope::Kyc {
                level: KycLevel::Accredited,
            }),
            _ => None,
        }
    }

    /// Convert to scope string
    pub fn to_string(&self) -> String {
        match self {
            ZkScope::OpenId => "openid".to_string(),
            ZkScope::Age { threshold } => format!("zk:age:{}+", threshold),
            ZkScope::Credential { credential_type } => match credential_type {
                Some(t) => format!("zk:credential:{}", t),
                None => "zk:credential".to_string(),
            },
            ZkScope::Kyc { level } => format!("zk:kyc:{}", level.as_str()),
        }
    }

    /// Convert to claim type (if applicable)
    pub fn to_claim_type(&self) -> Option<ClaimType> {
        match self {
            ZkScope::OpenId => None,
            ZkScope::Age { threshold } => Some(ClaimType::AgeAtLeast {
                threshold: *threshold,
            }),
            ZkScope::Credential { credential_type } => Some(ClaimType::HoldsCredential {
                credential_type: credential_type.clone().unwrap_or_else(|| "*".to_string()),
                issuer: None,
            }),
            ZkScope::Kyc { level } => Some(ClaimType::KycStatus {
                provider: "*".to_string(),
                level: *level,
                max_age_seconds: None,
            }),
        }
    }

    /// Check if this scope requires a ZK proof
    pub fn requires_proof(&self) -> bool {
        !matches!(self, ZkScope::OpenId)
    }
}

/// Parse multiple scopes from a space-separated string
pub fn parse_scopes(scopes: &str) -> Vec<ZkScope> {
    scopes
        .split_whitespace()
        .filter_map(ZkScope::parse)
        .collect()
}

/// Get the ZK scopes (excluding openid) that require proofs
pub fn get_proof_scopes(scopes: &[ZkScope]) -> Vec<&ZkScope> {
    scopes.iter().filter(|s| s.requires_proof()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scopes() {
        let scopes = parse_scopes("openid zk:age:21+ zk:kyc:basic");
        assert_eq!(scopes.len(), 3);

        assert!(matches!(&scopes[0], ZkScope::OpenId));
        assert!(matches!(&scopes[1], ZkScope::Age { threshold: 21 }));
        assert!(matches!(
            &scopes[2],
            ZkScope::Kyc {
                level: KycLevel::Basic
            }
        ));
    }

    #[test]
    fn test_scope_to_claim() {
        let scope = ZkScope::Age { threshold: 18 };
        let claim = scope.to_claim_type().unwrap();
        assert!(matches!(claim, ClaimType::AgeAtLeast { threshold: 18 }));
    }
}
