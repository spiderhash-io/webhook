#!/bin/bash
# Main orchestration script for Kubernetes testing scenario
# Usage: ./run_test.sh [basic|scaling|ingress|all]
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

source scripts/utils.sh

TEST_TYPE="${1:-basic}"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║       Kubernetes Local Testing Scenario                  ║"
echo "║       Testing: ${TEST_TYPE}                                      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Cleanup function
cleanup() {
    echo ""
    log_warn "Interrupted! Cleaning up..."
    stop_port_forward
    exit 1
}

trap cleanup INT TERM

# Step 1: Setup (if cluster doesn't exist)
if ! cluster_exists; then
    log_step "Cluster not found. Running setup..."
    ./scripts/setup.sh
else
    log_info "Using existing cluster '$CLUSTER_NAME'"

    # Check if image needs to be rebuilt
    read -p "Rebuild and reload Docker image? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        PROJECT_ROOT="$(get_project_root)"
        log_step "Rebuilding Docker image..."
        cd "$PROJECT_ROOT"
        if [ -f "docker/Dockerfile.smaller" ]; then
            docker build -t "$IMAGE_NAME" -f docker/Dockerfile.smaller .
        else
            docker build -t "$IMAGE_NAME" -f docker/Dockerfile .
        fi
        log_step "Loading image into kind..."
        kind load docker-image "$IMAGE_NAME" --name "$CLUSTER_NAME"
        cd "${SCRIPT_DIR}"
        log_success "Image reloaded"
    fi
fi

echo ""

# Step 2: Deploy with appropriate options
log_step "Deploying to cluster..."

case "$TEST_TYPE" in
    basic)
        ./scripts/deploy.sh
        ;;
    scaling)
        ./scripts/deploy.sh --with-hpa
        ;;
    ingress)
        ./scripts/deploy.sh --with-ingress
        ;;
    all)
        ./scripts/deploy.sh --all
        ;;
    *)
        log_error "Unknown test type: $TEST_TYPE"
        echo "Usage: $0 [basic|scaling|ingress|all]"
        exit 1
        ;;
esac

echo ""

# Step 3: Run tests
log_step "Running tests..."
./scripts/test.sh "$TEST_TYPE"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                    Test Run Complete                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Useful commands:"
echo "  View pods:      kubectl get pods -n $NAMESPACE"
echo "  View logs:      kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=core-webhook-module -f"
echo "  Port forward:   kubectl port-forward -n $NAMESPACE svc/webhook-service 8000:80"
echo "  Cleanup:        ./scripts/cleanup.sh"
echo ""
