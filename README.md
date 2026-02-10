# Fantasma

**Quantum-Resistant Zero-Knowledge Identity Layer**

Fantasma is a post-quantum secure identity verification system that enables users to prove identity attributes (age, credentials, KYC status) without revealing underlying personal data. It operates as an OIDC-compliant identity provider, allowing services to integrate via standard OAuth2/OIDC flows.

## Features

- **Post-Quantum Security**: Uses STARKs (hash-based proofs) and Dilithium signatures (NIST ML-DSA)
- **Zero-Knowledge Proofs**: Prove attributes without revealing data
- **OIDC Compatible**: Standard OAuth2/OIDC integration for existing services
- **Multiple Claim Types**:
  - Age verification (18+, 21+) without revealing birthdate
  - Credential verification (degrees, licenses) without details
  - KYC/AML status without personal data

## Architecture

```
fantasma/
├── circuits/              # Cairo circuits (STARK-based ZK proofs)
│   ├── age_verification.cairo
│   ├── credential_verification.cairo
│   └── kyc_verification.cairo
├── crates/
│   ├── fantasma-core/     # Core domain types
│   ├── fantasma-crypto/   # PQ cryptography (Dilithium, Poseidon)
│   ├── fantasma-stark/    # STARK prover/verifier
│   ├── fantasma-oidc/     # OIDC provider implementation
│   ├── fantasma-server/   # HTTP server (Axum)
│   ├── fantasma-wallet/   # User credential storage
│   ├── fantasma-issuer/   # Credential issuance
│   ├── fantasma-proof-store/  # STARK proof storage
│   └── fantasma-client-sdk/   # Client SDK
```

## Quick Start

### Prerequisites

- Rust 1.75+
- Scarb (Cairo package manager): `curl -L https://scarb.dev | sh`

### Build

```bash
# Build all crates
cargo build --workspace

# Build Cairo circuits
cd circuits && scarb build
```

### Run Server

```bash
# Start the OIDC server
cargo run -p fantasma-server

# Server runs at http://localhost:3000
```

### Test OIDC Flow

```bash
# Check discovery endpoint
curl http://localhost:3000/.well-known/openid-configuration

# Initiate authorization (demo client)
# Open in browser:
# http://localhost:3000/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/callback&scope=openid%20zk:age:21+&state=abc123
```

## OIDC Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Standard OIDC scope |
| `zk:age:18+` | Prove age ≥ 18 |
| `zk:age:21+` | Prove age ≥ 21 |
| `zk:credential` | Prove any credential |
| `zk:credential:degree` | Prove degree |
| `zk:credential:license` | Prove license |
| `zk:kyc:basic` | Prove basic KYC |
| `zk:kyc:enhanced` | Prove enhanced KYC |
| `zk:kyc:accredited` | Prove accredited status |

## ID Token Example

```json
{
  "iss": "https://fantasma.example",
  "sub": "zkid:abc123...",
  "aud": "your-client-id",
  "exp": 1707580800,
  "iat": 1707577200,
  "zk_age_claim": {
    "threshold": 21,
    "verified": true,
    "proof_ref": {
      "id": "prf_xyz789",
      "hash": "0xdef456...",
      "url": "https://proofs.fantasma.example/prf_xyz789"
    },
    "circuit_version": "age_verification_v1"
  }
}
```

## Security

- **STARKs**: Post-quantum secure (hash-based, no ECC)
- **Dilithium**: NIST-standardized PQ signature scheme
- **No Trusted Setup**: STARKs are transparent
- **Nullifiers**: Prevent proof replay
- **Domain Binding**: Different pseudonymous IDs per verifier

## License

MIT OR Apache-2.0
