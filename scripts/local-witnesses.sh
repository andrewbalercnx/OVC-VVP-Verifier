#!/bin/bash
# Start/stop local KERI witnesses for VVP development
#
# Usage:
#   ./scripts/local-witnesses.sh         # Start witnesses
#   ./scripts/local-witnesses.sh start   # Start witnesses
#   ./scripts/local-witnesses.sh stop    # Stop witnesses
#   ./scripts/local-witnesses.sh status  # Check status
#   ./scripts/local-witnesses.sh logs    # View logs
#   ./scripts/local-witnesses.sh health  # Check OOBI endpoints

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Witness configuration (from kli witness demo deterministic salts)
WITNESS_NAMES=("wan" "wil" "wes")
WITNESS_HTTP_PORTS=(5642 5643 5644)
WITNESS_TCP_PORTS=(5632 5633 5634)
WITNESS_AIDS=(
    "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"
    "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"
    "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"
)

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
        echo "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        echo -e "${RED}Error: Docker daemon is not running${NC}"
        echo "Please start Docker Desktop or the Docker daemon"
        exit 1
    fi
}

check_ports() {
    local ports_in_use=()

    for port in "${WITNESS_HTTP_PORTS[@]}" "${WITNESS_TCP_PORTS[@]}"; do
        if lsof -i ":$port" &> /dev/null; then
            ports_in_use+=("$port")
        fi
    done

    if [ ${#ports_in_use[@]} -gt 0 ]; then
        echo -e "${RED}Error: The following ports are already in use:${NC}"
        for port in "${ports_in_use[@]}"; do
            echo -e "  ${YELLOW}$port${NC}: $(lsof -i :$port -t 2>/dev/null | head -1 | xargs -I{} ps -p {} -o comm= 2>/dev/null || echo 'unknown process')"
        done
        echo ""
        echo "Please stop the conflicting services or use different ports."
        echo "Required ports: ${WITNESS_TCP_PORTS[*]} (TCP), ${WITNESS_HTTP_PORTS[*]} (HTTP)"
        return 1
    fi

    return 0
}

start_witnesses() {
    echo -e "${BLUE}Starting local KERI witnesses...${NC}"

    check_docker

    # Check port availability (per reviewer feedback)
    if ! check_ports; then
        exit 1
    fi

    # Start witnesses using docker-compose
    docker-compose up -d witnesses

    echo -e "${YELLOW}Waiting for witnesses to initialize...${NC}"

    # Wait for container to be healthy
    local max_wait=60
    local waited=0
    while [ $waited -lt $max_wait ]; do
        local health=$(docker inspect --format='{{.State.Health.Status}}' vvp-witnesses 2>/dev/null || echo "starting")
        if [ "$health" = "healthy" ]; then
            break
        fi
        sleep 2
        waited=$((waited + 2))
        echo -ne "\r  Waiting... ${waited}s"
    done
    echo ""

    # Verify witnesses are responding
    check_health
}

stop_witnesses() {
    echo -e "${YELLOW}Stopping local KERI witnesses...${NC}"
    docker-compose down
    echo -e "${GREEN}Witnesses stopped${NC}"
}

check_health() {
    echo -e "\n${BLUE}Checking witness health...${NC}"

    local all_healthy=true

    for i in "${!WITNESS_NAMES[@]}"; do
        local name="${WITNESS_NAMES[$i]}"
        local port="${WITNESS_HTTP_PORTS[$i]}"
        local aid="${WITNESS_AIDS[$i]}"

        # Check basic HTTP response
        if curl -s --connect-timeout 3 "http://127.0.0.1:$port/" > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} $name (port $port) - responding"

            # Check OOBI endpoint
            local oobi_url="http://127.0.0.1:$port/oobi/$aid/controller"
            local oobi_response=$(curl -s --connect-timeout 5 "$oobi_url" 2>/dev/null || echo "")
            if [ -n "$oobi_response" ] && [ ${#oobi_response} -gt 10 ]; then
                echo -e "    OOBI: ${GREEN}OK${NC} (${#oobi_response} bytes)"
            else
                echo -e "    OOBI: ${YELLOW}No response yet${NC}"
            fi
        else
            echo -e "  ${RED}✗${NC} $name (port $port) - not responding"
            all_healthy=false
        fi
    done

    echo ""
    if $all_healthy; then
        echo -e "${GREEN}All witnesses are healthy!${NC}"
        echo ""
        echo -e "${BLUE}Witness OOBI URLs:${NC}"
        for i in "${!WITNESS_NAMES[@]}"; do
            echo "  http://127.0.0.1:${WITNESS_HTTP_PORTS[$i]}/oobi/${WITNESS_AIDS[$i]}/controller"
        done
        echo ""
        echo -e "${BLUE}To configure verifier for local witnesses:${NC}"
        echo "  export VVP_LOCAL_WITNESS_URLS=http://127.0.0.1:5642,http://127.0.0.1:5643,http://127.0.0.1:5644"
        return 0
    else
        echo -e "${RED}Some witnesses are not healthy.${NC}"
        echo "Check logs with: $0 logs"
        return 1
    fi
}

show_logs() {
    echo -e "${BLUE}Witness logs (Ctrl+C to exit):${NC}"
    docker-compose logs -f witnesses
}

show_status() {
    echo -e "${BLUE}Container status:${NC}"
    docker-compose ps witnesses
    echo ""

    local container_running=$(docker ps -q -f name=vvp-witnesses 2>/dev/null)
    if [ -n "$container_running" ]; then
        check_health
    else
        echo -e "${YELLOW}Witnesses are not running.${NC}"
        echo "Start with: $0 start"
    fi
}

show_help() {
    echo "Local KERI Witness Manager for VVP Development"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start   Start the witness container (default)"
    echo "  stop    Stop and remove the witness container"
    echo "  status  Show container status and health"
    echo "  health  Check OOBI endpoint health"
    echo "  logs    Stream container logs"
    echo "  help    Show this help message"
    echo ""
    echo "Witnesses (from kli witness demo):"
    echo "  wan: HTTP 5642, TCP 5632, AID ${WITNESS_AIDS[0]}"
    echo "  wil: HTTP 5643, TCP 5633, AID ${WITNESS_AIDS[1]}"
    echo "  wes: HTTP 5644, TCP 5634, AID ${WITNESS_AIDS[2]}"
}

# Main command dispatch
case "${1:-start}" in
    start)
        start_witnesses
        ;;
    stop)
        stop_witnesses
        ;;
    status)
        show_status
        ;;
    health)
        check_health
        ;;
    logs)
        show_logs
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
