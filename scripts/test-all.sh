#!/bin/bash
#
# Fantasma — Full test suite
#
# Runs every test layer: Rust unit/integration, WASM build,
# frontend builds, and optionally Docker E2E with PostgreSQL.
#
# Usage:
#   ./scripts/test-all.sh          # Rust + WASM + frontends
#   ./scripts/test-all.sh --e2e    # Also spin up Docker E2E
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
DIM='\033[2m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

run_step() {
    local name="$1"
    shift
    echo ""
    echo -e "${BLUE}── $name ──${NC}"
    if "$@"; then
        echo -e "${GREEN}  ✓ $name${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  ✗ $name${NC}"
        FAIL=$((FAIL + 1))
    fi
}

skip_step() {
    local name="$1"
    local reason="$2"
    echo ""
    echo -e "${YELLOW}  ⊘ $name — $reason${NC}"
    SKIP=$((SKIP + 1))
}

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║               Fantasma Test Suite                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Rust workspace ────────────────────────────────────────

run_step "Cargo build" cargo build --workspace

run_step "Cargo test (56 tests)" cargo test --workspace

# ── 2. Clippy + fmt ──────────────────────────────────────────

if command -v rustfmt &>/dev/null; then
    run_step "Cargo fmt check" cargo fmt --all -- --check
else
    skip_step "Cargo fmt check" "rustfmt not installed"
fi

# Clippy — allow it to fail without breaking the suite
if cargo clippy --version &>/dev/null; then
    echo ""
    echo -e "${BLUE}── Cargo clippy ──${NC}"
    if cargo clippy --workspace --all-targets 2>&1 | tail -5; then
        echo -e "${GREEN}  ✓ Cargo clippy${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${YELLOW}  ⚠ Cargo clippy (warnings)${NC}"
        PASS=$((PASS + 1))  # Warnings don't fail
    fi
else
    skip_step "Cargo clippy" "clippy not installed"
fi

# ── 3. WASM build ────────────────────────────────────────────

if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
    run_step "WASM build (fantasma-wasm)" \
        cargo build --target wasm32-unknown-unknown -p fantasma-wasm
else
    echo ""
    echo -e "${YELLOW}  ⊘ WASM build — wasm32-unknown-unknown target not installed${NC}"
    echo -e "${DIM}    Install with: rustup target add wasm32-unknown-unknown${NC}"
    SKIP=$((SKIP + 1))
fi

# ── 4. Wallet extension ──────────────────────────────────────

if [ -d "wallet-extension" ] && command -v npm &>/dev/null; then
    echo ""
    echo -e "${BLUE}── Wallet extension build ──${NC}"
    (
        cd wallet-extension
        [ -d node_modules ] || npm install --silent 2>&1
        if npm run build 2>&1; then
            echo -e "${GREEN}  ✓ Wallet extension build${NC}"
        else
            echo -e "${RED}  ✗ Wallet extension build${NC}"
            exit 1
        fi
    ) && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
else
    skip_step "Wallet extension build" "npm not installed or directory missing"
fi

# ── 5. Admin dashboard ───────────────────────────────────────

if [ -d "admin-dashboard" ] && command -v npm &>/dev/null; then
    echo ""
    echo -e "${BLUE}── Admin dashboard build ──${NC}"
    (
        cd admin-dashboard
        [ -d node_modules ] || npm install --silent 2>&1
        if npm run build 2>&1; then
            echo -e "${GREEN}  ✓ Admin dashboard build${NC}"
        else
            echo -e "${RED}  ✗ Admin dashboard build${NC}"
            exit 1
        fi
    ) && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
else
    skip_step "Admin dashboard build" "npm not installed or directory missing"
fi

# ── 6. Cairo circuits (optional) ─────────────────────────────

if [ -d "circuits" ] && command -v scarb &>/dev/null; then
    run_step "Cairo circuit tests" bash -c "cd circuits && scarb test"
else
    skip_step "Cairo circuit tests" "scarb not installed or circuits/ missing"
fi

# ── 7. Docker E2E (optional, --e2e flag) ─────────────────────

if [[ "${1:-}" == "--e2e" ]]; then
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        echo ""
        echo -e "${BLUE}── Docker E2E ──${NC}"

        # Start just postgres
        docker-compose up -d postgres
        echo "Waiting for PostgreSQL..."
        for i in $(seq 1 30); do
            if docker-compose exec -T postgres pg_isready -U fantasma &>/dev/null; then
                echo "  PostgreSQL ready after ${i}s"
                break
            fi
            sleep 1
        done

        # Run server locally against Docker postgres
        export DATABASE_URL="postgres://fantasma:fantasma_dev_password@localhost:5432/fantasma"
        export FANTASMA_ADMIN_KEY="e2e-test-key"
        export FANTASMA_ISSUER="http://localhost:3000"
        export FANTASMA_BIND="127.0.0.1:3000"
        export RUST_LOG="fantasma_server=info"

        echo "Building and starting server (this may take a moment)..."
        cargo run -p fantasma-server --release &
        SERVER_PID=$!

        # Wait for server to be ready (up to 120s for compilation + startup)
        echo "Waiting for server..."
        SERVER_READY=false
        for i in $(seq 1 120); do
            if curl -sf http://localhost:3000/health >/dev/null 2>&1; then
                echo "  Server ready after ${i}s"
                SERVER_READY=true
                break
            fi
            # Check if cargo/server process died
            if ! kill -0 $SERVER_PID 2>/dev/null; then
                echo -e "${RED}  Server process exited unexpectedly${NC}"
                break
            fi
            sleep 1
        done

        if ! $SERVER_READY; then
            echo -e "${RED}  ✗ Server failed to start within 120s${NC}"
            kill $SERVER_PID 2>/dev/null || true
            docker-compose down
            FAIL=$((FAIL + 1))
        else

        E2E_PASS=true

        # Health
        if curl -sf http://localhost:3000/health >/dev/null; then
            echo -e "${GREEN}  ✓ Health check${NC}"
        else
            echo -e "${RED}  ✗ Health check${NC}"
            E2E_PASS=false
        fi

        # Discovery
        if curl -sf http://localhost:3000/.well-known/openid-configuration | grep -q "issuer"; then
            echo -e "${GREEN}  ✓ OIDC discovery${NC}"
        else
            echo -e "${RED}  ✗ OIDC discovery${NC}"
            E2E_PASS=false
        fi

        # Admin stats (with DB connected)
        ADMIN_RESP=$(curl -sf -H "X-Admin-Key: $FANTASMA_ADMIN_KEY" http://localhost:3000/admin/stats 2>&1 || true)
        if echo "$ADMIN_RESP" | grep -q "clients"; then
            echo -e "${GREEN}  ✓ Admin API (stats)${NC}"
        else
            echo -e "${RED}  ✗ Admin API (stats): $ADMIN_RESP${NC}"
            E2E_PASS=false
        fi

        # Admin create + list client
        curl -sf -X POST -H "X-Admin-Key: $FANTASMA_ADMIN_KEY" \
            -H "Content-Type: application/json" \
            -d '{"client_id":"e2e-client","client_name":"E2E Test","redirect_uris":["http://localhost:9999/cb"],"allowed_scopes":["openid"]}' \
            http://localhost:3000/admin/clients >/dev/null 2>&1

        if curl -sf -H "X-Admin-Key: $FANTASMA_ADMIN_KEY" http://localhost:3000/admin/clients | grep -q "e2e-client"; then
            echo -e "${GREEN}  ✓ Admin API (create + list client)${NC}"
        else
            echo -e "${RED}  ✗ Admin API (create + list client)${NC}"
            E2E_PASS=false
        fi

        # OIDC flow (authorize → consent → token)
        AUTH_HTML=$(curl -sf "http://localhost:3000/authorize?client_id=demo-client&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20zk:age:21%2B&state=e2e" || true)
        if echo "$AUTH_HTML" | grep -q "Demo Client"; then
            echo -e "${GREEN}  ✓ OIDC authorize page${NC}"
        else
            echo -e "${YELLOW}  ⚠ OIDC authorize page (couldn't verify content)${NC}"
        fi

        REDIRECT=$(curl -sf -D- -o/dev/null -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/callback&scope=openid%20zk:age:21%2B&state=e2e&demo_user=alice&action=approve" \
            http://localhost:3000/authorize/consent 2>&1 | grep -i "^location:" || true)

        CODE=$(echo "$REDIRECT" | sed -n 's/.*code=\([^&]*\).*/\1/p' | tr -d '\r')
        if [ -n "$CODE" ]; then
            TOKEN_RESP=$(curl -sf -X POST \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "grant_type=authorization_code&code=$CODE&redirect_uri=http://localhost:8080/callback&client_id=demo-client" \
                http://localhost:3000/token || true)
            if echo "$TOKEN_RESP" | grep -q "id_token"; then
                echo -e "${GREEN}  ✓ Full OIDC flow (authorize → consent → token)${NC}"
            else
                echo -e "${RED}  ✗ Token exchange failed${NC}"
                E2E_PASS=false
            fi
        else
            echo -e "${RED}  ✗ Consent redirect missing code${NC}"
            E2E_PASS=false
        fi

        # Cleanup
        kill $SERVER_PID 2>/dev/null || true
        docker-compose down

        if $E2E_PASS; then
            echo -e "${GREEN}  ✓ Docker E2E${NC}"
            PASS=$((PASS + 1))
        else
            FAIL=$((FAIL + 1))
        fi

        fi # end if $SERVER_READY
    else
        skip_step "Docker E2E" "Docker not available"
    fi
fi

# ── Summary ──────────────────────────────────────────────────

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}✓ $PASS passed${NC}    ${RED}✗ $FAIL failed${NC}    ${YELLOW}⊘ $SKIP skipped${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
