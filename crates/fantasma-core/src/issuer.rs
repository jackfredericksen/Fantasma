//! Issuer types for Fantasma
//!
//! Issuers are trusted entities that create and sign credentials.

use serde::{Deserialize, Serialize};

/// Unique identifier for an issuer
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IssuerId(pub String);

impl IssuerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IssuerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Trust anchor defining how an issuer is trusted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustAnchor {
    /// Government-backed issuer
    Government {
        /// Country code (ISO 3166-1 alpha-2)
        country: String,
        /// Government department/agency
        department: Option<String>,
    },

    /// Accredited institution (university, professional body)
    Accredited {
        /// Name of the accrediting body
        accreditor: String,
        /// Accreditation ID/number
        accreditation_id: Option<String>,
    },

    /// Part of a trust framework
    TrustFramework {
        /// Framework identifier
        framework_id: String,
        /// Role within the framework
        role: Option<String>,
    },

    /// Self-declared issuer (lower trust level)
    SelfDeclared {
        /// Domain for verification
        domain: String,
    },
}

impl TrustAnchor {
    /// Get a trust level (higher = more trusted)
    pub fn trust_level(&self) -> u8 {
        match self {
            TrustAnchor::Government { .. } => 100,
            TrustAnchor::Accredited { .. } => 80,
            TrustAnchor::TrustFramework { .. } => 60,
            TrustAnchor::SelfDeclared { .. } => 20,
        }
    }
}

/// Information about a credential issuer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerInfo {
    /// Unique identifier for this issuer
    pub id: IssuerId,

    /// Human-readable name
    pub name: String,

    /// Issuer's public key for signature verification (Dilithium)
    pub public_key: Vec<u8>,

    /// How this issuer is trusted
    pub trust_anchor: TrustAnchor,

    /// URL for issuer metadata
    pub metadata_url: Option<String>,

    /// URL for credential status (revocation checking)
    pub status_url: Option<String>,

    /// Supported credential schemas
    pub supported_schemas: Vec<String>,
}

impl IssuerInfo {
    /// Check if this issuer can issue a specific credential type
    pub fn supports_schema(&self, schema: &str) -> bool {
        self.supported_schemas.iter().any(|s| s == schema)
    }
}

/// Registry entry for tracking issuer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerRegistryEntry {
    /// The issuer information
    pub info: IssuerInfo,

    /// Whether this issuer is currently active
    pub active: bool,

    /// When this entry was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Current Merkle root of valid credentials
    #[serde(with = "hex_bytes")]
    pub credentials_root: [u8; 32],
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))
    }
}
