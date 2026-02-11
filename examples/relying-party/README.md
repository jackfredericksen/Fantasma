# Demo Relying Party

Test app showing the complete Fantasma OAuth2/OIDC flow with ZK claims.

## Quick Start

```bash
# Terminal 1: Start Fantasma server
cd ../..
cargo run -p fantasma-server

# Terminal 2: Start this demo app
npm install
npm start
```

Open http://localhost:8080

## What It Does

1. Shows a login page with claim options (Age 18+, Age 21+, KYC)
2. Redirects to Fantasma `/authorize` with ZK scopes
3. Handles callback with authorization code
4. Exchanges code for tokens at `/token`
5. Displays the ID token with verified ZK claims

## Configuration

Environment variables:

```bash
FANTASMA_URL=http://localhost:3000  # Fantasma server URL
```

## OAuth2 Details

- **Client ID**: `demo-rp`
- **Redirect URI**: `http://localhost:8080/callback`
- **Scopes**: `openid zk:age:18+ zk:age:21+ zk:kyc:basic`
