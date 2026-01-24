#!/bin/bash
# Shared utility functions for Kubernetes testing scenario

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Cluster name (must match kind-cluster.yaml)
CLUSTER_NAME="webhook-test"
NAMESPACE="webhook-system"
IMAGE_NAME="webhook-module:local"

# Get script directory
get_script_dir() {
    echo "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
}

# Get scenario directory (parent of scripts/)
get_scenario_dir() {
    echo "$(cd "$(get_script_dir)/.." && pwd)"
}

# Get project root directory
get_project_root() {
    echo "$(cd "$(get_scenario_dir)/../../.." && pwd)"
}

# Logging functions
log_step() {
    echo -e "${BLUE}==>${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_info() {
    echo -e "  $1"
}

# Check if a command exists
check_command() {
    local cmd="$1"
    local install_hint="$2"

    if ! command -v "$cmd" &> /dev/null; then
        log_error "Command '$cmd' not found"
        if [ -n "$install_hint" ]; then
            log_info "Install hint: $install_hint"
        fi
        return 1
    fi
    return 0
}

# Check all prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    local missing=0

    if ! check_command "docker" "https://docs.docker.com/get-docker/"; then
        missing=1
    fi

    if ! check_command "kind" "brew install kind OR go install sigs.k8s.io/kind@latest"; then
        missing=1
    fi

    if ! check_command "kubectl" "brew install kubectl OR https://kubernetes.io/docs/tasks/tools/"; then
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        log_error "Missing prerequisites. Please install the required tools."
        return 1
    fi

    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker."
        return 1
    fi

    log_success "All prerequisites satisfied"
    return 0
}

# Check if kind cluster exists
cluster_exists() {
    kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"
}

# Wait for deployment to be ready
wait_for_deployment() {
    local deployment="$1"
    local namespace="${2:-$NAMESPACE}"
    local timeout="${3:-120}"

    log_step "Waiting for deployment '$deployment' to be ready (timeout: ${timeout}s)..."

    if kubectl rollout status deployment/"$deployment" -n "$namespace" --timeout="${timeout}s" 2>/dev/null; then
        log_success "Deployment '$deployment' is ready"
        return 0
    else
        log_error "Deployment '$deployment' failed to become ready"
        return 1
    fi
}

# Wait for pods to be running
wait_for_pods() {
    local label="$1"
    local namespace="${2:-$NAMESPACE}"
    local timeout="${3:-120}"

    log_step "Waiting for pods with label '$label' to be running..."

    local end_time=$(($(date +%s) + timeout))
    while [ $(date +%s) -lt $end_time ]; do
        local running=$(kubectl get pods -n "$namespace" -l "$label" -o jsonpath='{.items[*].status.phase}' 2>/dev/null | tr ' ' '\n' | grep -c "Running" || echo "0")
        local total=$(kubectl get pods -n "$namespace" -l "$label" --no-headers 2>/dev/null | wc -l | tr -d ' ')

        if [ "$total" -gt 0 ] && [ "$running" -eq "$total" ]; then
            log_success "All $total pod(s) are running"
            return 0
        fi

        echo -n "."
        sleep 2
    done

    echo ""
    log_error "Pods did not become ready within ${timeout}s"
    return 1
}

# Port forward in background
start_port_forward() {
    local service="$1"
    local local_port="$2"
    local remote_port="$3"
    local namespace="${4:-$NAMESPACE}"
    local pid_file="$(get_scenario_dir)/logs/port-forward.pid"

    # Kill existing port forward if any
    stop_port_forward

    log_step "Starting port-forward: localhost:$local_port -> $service:$remote_port"
    kubectl port-forward -n "$namespace" "svc/$service" "$local_port:$remote_port" &>/dev/null &
    echo $! > "$pid_file"

    # Wait for port to be available
    sleep 2
    if ! curl -s -o /dev/null -w '' "http://localhost:$local_port/health" 2>/dev/null; then
        sleep 3  # Give it more time
    fi

    log_success "Port-forward started (PID: $(cat $pid_file))"
}

# Stop port forward
stop_port_forward() {
    local pid_file="$(get_scenario_dir)/logs/port-forward.pid"

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            log_info "Stopped port-forward (PID: $pid)"
        fi
        rm -f "$pid_file"
    fi
}

# Send test webhook
send_webhook() {
    local endpoint="$1"
    local data="$2"
    local auth_header="${3:-Authorization: Bearer test_token_123}"
    local base_url="${4:-http://localhost:8000}"

    curl -s -w "\n%{http_code}" \
        -X POST "$base_url/webhook/$endpoint" \
        -H "Content-Type: application/json" \
        -H "$auth_header" \
        -d "$data"
}

# Check endpoint health
check_health() {
    local base_url="${1:-http://localhost:8000}"

    local response=$(curl -s -o /dev/null -w "%{http_code}" "$base_url/health" 2>/dev/null)
    [ "$response" = "200" ]
}
