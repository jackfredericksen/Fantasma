#!/bin/bash
#
# Start Fantasma development environment
# Usage: ./scripts/dev.sh
#

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              Fantasma Development Server                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: cargo not found. Install Rust first.${NC}"
    exit 1
fi

# Build the server
echo -e "${BLUE}Building fantasma-server...${NC}"
cargo build -p fantasma-server --release

# Start server in background
echo -e "${GREEN}Starting Fantasma server on http://localhost:3000${NC}"
FANTASMA_ISSUER="http://localhost:3000" \
FANTASMA_BIND="0.0.0.0:3000" \
cargo run -p fantasma-server --release &
SERVER_PID=$!

# Wait for server to start
echo "Waiting for server to start..."
sleep 3

# Check if server is running
if curl -s http://localhost:3000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Server is running${NC}"
else
    echo -e "${RED}✗ Server failed to start${NC}"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Check if demo RP needs npm install
if [ -d "examples/relying-party" ]; then
    cd examples/relying-party
    if [ ! -d "node_modules" ]; then
        echo -e "${BLUE}Installing demo relying party dependencies...${NC}"
        npm install
    fi

    echo -e "${GREEN}Starting demo relying party on http://localhost:8080${NC}"
    npm start &
    RP_PID=$!
    cd "$ROOT_DIR"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Development environment ready!${NC}"
echo ""
echo "  Fantasma Server:  http://localhost:3000"
echo "  Demo App:         http://localhost:8080"
echo ""
echo "  OIDC Discovery:   http://localhost:3000/.well-known/openid-configuration"
echo ""
echo "Press Ctrl+C to stop all services"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

# Cleanup on exit
cleanup() {
    echo ""
    echo "Stopping services..."
    kill $SERVER_PID 2>/dev/null || true
    kill $RP_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait
wait
