#!/bin/bash
# Cleanup script: Delete kind cluster and cleanup resources
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

SCENARIO_DIR="$(get_scenario_dir)"

# Parse arguments
CLEAN_LOGS=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --logs)
            CLEAN_LOGS=true
            shift
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Usage: $0 [--logs] [--force|-f]"
            exit 1
            ;;
    esac
done

echo ""
echo "=========================================="
echo "Kubernetes Test Scenario - Cleanup"
echo "=========================================="
echo ""

# Stop any port forwards
stop_port_forward

# Check if cluster exists
if cluster_exists; then
    if [ "$FORCE" = false ]; then
        read -p "Delete kind cluster '$CLUSTER_NAME'? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Cleanup cancelled"
            exit 0
        fi
    fi

    log_step "Deleting kind cluster '$CLUSTER_NAME'..."
    kind delete cluster --name "$CLUSTER_NAME"
    log_success "Kind cluster deleted"
else
    log_info "Kind cluster '$CLUSTER_NAME' does not exist"
fi

# Clean up kubeconfig entries
log_step "Cleaning up kubeconfig context..."
kubectl config delete-context "kind-${CLUSTER_NAME}" &>/dev/null || true
kubectl config delete-cluster "kind-${CLUSTER_NAME}" &>/dev/null || true
log_success "Kubeconfig cleaned"

# Clean logs if requested
if [ "$CLEAN_LOGS" = true ]; then
    log_step "Cleaning log files..."
    rm -f "${SCENARIO_DIR}/logs/"*.log
    rm -f "${SCENARIO_DIR}/logs/"*.txt
    rm -f "${SCENARIO_DIR}/logs/port-forward.pid"
    log_success "Log files cleaned"
fi

# Remove any temporary files
rm -f "${SCENARIO_DIR}/kubeconfig" 2>/dev/null || true

echo ""
echo "=========================================="
log_success "Cleanup complete!"
echo "=========================================="
echo ""
echo "To recreate the cluster, run: ./scripts/setup.sh"
echo ""
