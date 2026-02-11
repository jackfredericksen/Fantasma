# 🍉Support Humanitarian Efforts in Palestine🍉

The ongoing humanitarian crisis in Palestine has left millions in urgent need of aid. If you're looking to make a difference, consider supporting trusted organizations working on the ground to provide food, medical care, and essential relief:
- [UN Crisis Relief – Occupied Palestinian Territory Humanitarian Fund](https://crisisrelief.un.org/en/opt-crisis)
- [Palestine Children's Relief Fund ](https://www.pcrf.net/)
- [Doctors Without Borders](https://www.doctorswithoutborders.org/)
- [Anera (American Near East Refugee Aid)](https://www.anera.org/)
- [Save the Children](https://www.savethechildren.org/us/where-we-work/west-bank-gaza)
<br></br>


# Fantasma

Post-quantum zero-knowledge identity provider. Prove who you are without revealing what you are.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   User Wallet          Fantasma Server              Relying Party          │
│   ───────────          ──────────────              ──────────────          │
│                                                                             │
│   ┌───────────┐        ┌─────────────┐             ┌─────────────┐         │
│   │Credentials│───────▶│ OIDC + ZK   │◀────────────│  OAuth2     │         │
│   │  (local)  │  STARK │   Proofs    │  Standard   │   Client    │         │
│   └───────────┘  proof └─────────────┘  OIDC flow  └─────────────┘         │
│                                                                             │
│   Dilithium sigs       Cairo/STARK                 No code changes         │
│   AES-256-GCM          PostgreSQL                  needed                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Why

Existing identity solutions force a tradeoff: either share everything (OAuth with profile scopes) or build custom integrations. Fantasma sits in the middle—standard OIDC that any service can integrate, but the tokens contain cryptographic proofs instead of raw data.

The proofs are STARKs, not SNARKs. This means:

- No trusted setup ceremony
- Quantum-resistant (hash-based, not ECC)
- Larger proofs (~100KB vs ~200B), stored server-side with hash references in JWTs

## Architecture

```
fantasma/
├── circuits/                    # Cairo 1.0 programs (compiled to STARK circuits)
│   └── src/
│       ├── age_verification.cairo
│       ├── credential_verification.cairo
│       └── kyc_verification.cairo
│
├── crates/
│   ├── fantasma-core/           # Credential, ClaimType, AttributeValue
│   ├── fantasma-crypto/         # Dilithium (pqcrypto), Poseidon, SHA3
│   ├── fantasma-stark/          # CairoRunner, witness generation, proof types
│   ├── fantasma-oidc/           # Discovery, token generation, JWKS
│   ├── fantasma-db/             # sqlx + PostgreSQL repositories
│   ├── fantasma-server/         # Axum HTTP server
│   ├── fantasma-wallet/         # Encrypted credential storage
│   ├── fantasma-issuer/         # Credential signing
│   ├── fantasma-proof-store/    # Proof persistence + retrieval
│   └── fantasma-client-sdk/     # RP integration helpers
│
└── wallet-extension/            # Chrome/Firefox extension
    └── src/
        ├── background/          # Service worker, proof orchestration
        ├── content/             # Page injection, window.fantasma API
        └── popup/               # Wallet UI
```

## Protocol Flow

```
    ┌────────┐                    ┌─────────┐                    ┌────────┐
    │  User  │                    │Fantasma │                    │Service │
    └───┬────┘                    └────┬────┘                    └───┬────┘
        │                              │                             │
        │         1. /authorize?scope=openid zk:age:21+              │
        │◀─────────────────────────────┼─────────────────────────────│
        │                              │                             │
        │  2. Consent + credential     │                             │
        │     selection (wallet UI)    │                             │
        ├─────────────────────────────▶│                             │
        │                              │                             │
        │  3. Generate STARK proof     │                             │
        │     (Cairo execution)        │                             │
        │         ┌────────────────────┤                             │
        │         │ witness:           │                             │
        │         │   birthdate (priv) │                             │
        │         │   threshold (pub)  │                             │
        │         │   commitment (pub) │                             │
        │         └────────────────────┤                             │
        │                              │                             │
        │  4. Store proof, return ID   │                             │
        │◀─────────────────────────────┤                             │
        │                              │                             │
        │         5. Redirect with code                              │
        │─────────────────────────────────────────────────────────▶ │
        │                              │                             │
        │                              │  6. Exchange code for token │
        │                              │◀────────────────────────────│
        │                              │                             │
        │                              │  7. ID token + proof_ref    │
        │                              │────────────────────────────▶│
        │                              │                             │
        │                              │  8. (optional) GET /proofs/id
        │                              │◀────────────────────────────│
        │                              │  9. Full STARK proof bytes  │
        │                              │────────────────────────────▶│
```

## Cryptographic Stack

| Layer       | Primitive            | Implementation                                       |
|-------------|----------------------|------------------------------------------------------|
| Signatures  | Dilithium3 (ML-DSA)  | `pqcrypto-dilithium`                                 |
| Commitments | Poseidon             | STARK-friendly, ~8x faster than Pedersen in circuits |
| Proofs      | STARK                | Cairo VM → execution trace → stone-prover/stwo       |
| Hashing     | SHA3-256, Keccak     | credential IDs, nullifiers                           |
| Encryption  | AES-256-GCM          | wallet credential storage                            |
| KDF         | PBKDF2 (600k rounds) | wallet password → encryption key                     |

## Database Schema

```sql
-- Core tables (PostgreSQL)

clients           -- OAuth2 client registrations
auth_codes        -- Authorization codes (10 min TTL)
refresh_tokens    -- Long-lived tokens (hashed)
proofs            -- STARK proof blobs (~100KB each)
nullifiers        -- Replay prevention (hash + domain)
credentials       -- Encrypted user credentials
issuers           -- Trusted credential issuers + Dilithium pubkeys
audit_log         -- Security events
```

See [migrations](crates/fantasma-db/migrations/20240210_001_initial.sql) for full schema.

## ID Token Structure

```json
{
  "iss": "https://id.example.com",
  "sub": "zkid:a]3f7b2c1d...",
  "aud": "client_abc",
  "iat": 1707577200,
  "exp": 1707580800,
  "nonce": "n-0S6_WzA2Mj",

  "zk_claims": {
    "age": {
      "threshold": 21,
      "satisfied": true,
      "proof_id": "prf_7x9k2m",
      "circuit": "age_verification_v1",
      "verified_at": 1707577200
    },
    "kyc": {
      "level": "basic",
      "satisfied": true,
      "proof_id": "prf_8y0l3n",
      "circuit": "kyc_verification_v1"
    }
  }
}
```

The `sub` claim is a domain-specific pseudonym: `SHA3(master_secret || service_domain)`. Same user, different `sub` per service. Unlinkable across services.

## ZK Scopes

Request claims via OIDC scopes:

```
openid                    # required
zk:age:18+               # prove age ≥ 18
zk:age:21+               # prove age ≥ 21
zk:age:65+               # prove age ≥ 65 (senior discounts)
zk:kyc:basic             # KYC level 1
zk:kyc:enhanced          # KYC level 2 (FATF compliant)
zk:kyc:accredited        # accredited investor status
zk:credential:degree     # holds academic degree
zk:credential:license    # holds professional license
zk:credential:membership # membership in org
```

## Running

```bash
# Prerequisites: Rust 1.75+, PostgreSQL 15+

# Build
cargo build --workspace --release

# Database setup
createdb fantasma
export DATABASE_URL="postgres://localhost/fantasma"
cargo run -p fantasma-db --bin migrate  # or use sqlx-cli

# Run server
FANTASMA_ISSUER="http://localhost:3000" \
FANTASMA_BIND="0.0.0.0:3000" \
cargo run -p fantasma-server --release

# Verify
curl -s http://localhost:3000/.well-known/openid-configuration | jq .
```

## Wallet Extension

The browser extension ([wallet-extension/](wallet-extension/)) provides:

- Encrypted credential storage (IndexedDB + AES-256-GCM)
- `window.fantasma` API for web apps
- In-page authorization consent UI
- Auto-lock with configurable timeout

```javascript
// Check if wallet is available
if (window.fantasma?.isInstalled) {
  const { connected } = await window.fantasma.connect();

  if (connected) {
    // Request authorization
    const result = await window.fantasma.authorize({
      client_id: 'your-app',
      redirect_uri: 'https://yourapp.com/callback',
      scope: 'openid zk:age:21+',
      state: crypto.randomUUID()
    });
  }
}
```

Build the extension:

```bash
cd wallet-extension
npm install
npm run build
# Load dist/ as unpacked extension in Chrome
```

## Cairo Circuits

Age verification circuit (simplified):

```cairo
#[executable]
fn verify_age(
    // Private inputs (witness)
    birthdate: u32,        // YYYYMMDD format
    salt: felt252,

    // Public inputs
    threshold: u8,         // minimum age
    current_date: u32,     // YYYYMMDD
    commitment: felt252,   // poseidon(birthdate, salt)
) {
    // Verify commitment matches
    let computed = poseidon_hash(birthdate.into(), salt);
    assert(computed == commitment, 'invalid commitment');

    // Calculate age
    let birth_year = birthdate / 10000;
    let current_year = current_date / 10000;
    let age = current_year - birth_year;

    // Adjust for birthday not yet reached
    let birth_mmdd = birthdate % 10000;
    let current_mmdd = current_date % 10000;
    let age = if current_mmdd < birth_mmdd { age - 1 } else { age };

    // Assert threshold
    assert(age >= threshold.into(), 'age below threshold');
}
```

Compile with Scarb:

```bash
cd circuits
scarb build
```

## Trade-offs

|                     | Fantasma (STARKs) | SNARK-based alternatives |
|---------------------|-------------------|--------------------------|
| Quantum resistance  | Yes               | No                       |
| Trusted setup       | None              | Required                 |
| Proof size          | ~100 KB           | ~200 bytes               |
| Proving time        | 10-30s            | 1-5s                     |
| Verification time   | ~50ms             | ~5ms                     |
| Tooling maturity    | Growing           | Established              |

We chose quantum resistance over proof size. Proofs are stored server-side; JWTs contain only a hash reference.

## Security Considerations

- **Nullifiers**: Each proof includes a nullifier = `hash(credential_id, domain, nonce)`. Prevents replay across and within domains.
- **Domain binding**: Pseudonymous IDs are domain-specific. Cannot correlate users across services.
- **Credential freshness**: Proofs include a verification timestamp. Verifiers can enforce max age.
- **Issuer trust**: Verifiers maintain allowlists of trusted issuer public keys.

## License

MIT OR Apache-2.0
