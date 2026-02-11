#!/bin/bash
#
# Docker development commands for Fantasma
# Usage: ./scripts/docker.sh [command]
#
# Commands:
#   up        Start all services
#   down      Stop all services
#   demo      Start with demo relying party
#   logs      View server logs
#   shell     Open a shell in the server container
#   rebuild   Rebuild and restart services
#   clean     Remove all containers and volumes

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

show_help() {
    echo -e "${BLUE}Fantasma Docker Development${NC}"
    echo ""
    echo "Usage: ./scripts/docker.sh [command]"
    echo ""
    echo "Commands:"
    echo "  up        Start Fantasma server and PostgreSQL"
    echo "  demo      Start with demo relying party"
    echo "  down      Stop all services"
    echo "  logs      View server logs (follow)"
    echo "  shell     Open shell in server container"
    echo "  rebuild   Rebuild and restart services"
    echo "  clean     Remove containers, volumes, and images"
    echo "  status    Show container status"
    echo ""
}

case "${1:-help}" in
    up)
        echo -e "${GREEN}Starting Fantasma...${NC}"
        docker compose up -d
        echo ""
        echo -e "${GREEN}Services started:${NC}"
        echo "  Fantasma Server: http://localhost:3000"
        echo "  PostgreSQL:      localhost:5432"
        echo ""
        echo "View logs: ./scripts/docker.sh logs"
        ;;

    demo)
        echo -e "${GREEN}Starting Fantasma with demo app...${NC}"
        docker compose --profile demo up -d
        echo ""
        echo -e "${GREEN}Services started:${NC}"
        echo "  Fantasma Server: http://localhost:3000"
        echo "  Demo App:        http://localhost:8080"
        echo "  PostgreSQL:      localhost:5432"
        ;;

    down)
        echo -e "${YELLOW}Stopping all services...${NC}"
        docker compose --profile demo down
        echo -e "${GREEN}Done.${NC}"
        ;;

    logs)
        docker compose logs -f fantasma-server
        ;;

    shell)
        docker compose exec fantasma-server /bin/bash
        ;;

    rebuild)
        echo -e "${YELLOW}Rebuilding and restarting...${NC}"
        docker compose build --no-cache fantasma-server
        docker compose up -d
        echo -e "${GREEN}Done.${NC}"
        ;;

    clean)
        echo -e "${RED}This will remove all containers, volumes, and images.${NC}"
        read -p "Are you sure? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker compose --profile demo down -v --rmi local
            echo -e "${GREEN}Cleaned.${NC}"
        fi
        ;;

    status)
        docker compose ps
        ;;

    help|--help|-h)
        show_help
        ;;

    *)
        echo -e "${RED}Unknown command: $1${NC}"
        show_help
        exit 1
        ;;
esac
