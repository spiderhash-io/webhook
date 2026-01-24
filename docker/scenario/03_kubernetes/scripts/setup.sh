#!/bin/bash
# Setup script: Create kind cluster and load Docker image
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

SCENARIO_DIR="$(get_scenario_dir)"
PROJECT_ROOT="$(get_project_root)"

echo ""
echo "=========================================="
echo "Kubernetes Test Scenario - Setup"
echo "=========================================="
echo ""

# Check prerequisites
check_prerequisites || exit 1

# Check if cluster already exists
if cluster_exists; then
    log_warn "Kind cluster '$CLUSTER_NAME' already exists"
    read -p "Delete and recreate? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_step "Deleting existing cluster..."
        kind delete cluster --name "$CLUSTER_NAME"
    else
        log_info "Using existing cluster"
        # Still need to build and load image
    fi
fi

# Create kind cluster if it doesn't exist
if ! cluster_exists; then
    log_step "Creating kind cluster '$CLUSTER_NAME'..."
    kind create cluster --config "${SCENARIO_DIR}/config/kind-cluster.yaml"
    log_success "Kind cluster created"
fi

# Set kubectl context
log_step "Setting kubectl context..."
kubectl cluster-info --context "kind-${CLUSTER_NAME}"

# Build Docker image
log_step "Building Docker image..."
cd "$PROJECT_ROOT"

if [ -f "docker/Dockerfile.smaller" ]; then
    docker build -t "$IMAGE_NAME" -f docker/Dockerfile.smaller .
else
    # Fallback to main Dockerfile
    docker build -t "$IMAGE_NAME" -f docker/Dockerfile .
fi
log_success "Docker image built: $IMAGE_NAME"

# Load image into kind cluster
log_step "Loading image into kind cluster..."
kind load docker-image "$IMAGE_NAME" --name "$CLUSTER_NAME"
log_success "Image loaded into kind cluster"

echo ""
echo "=========================================="
log_success "Setup complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Deploy manifests:  ./scripts/deploy.sh"
echo "  2. Run tests:         ./scripts/test.sh"
echo "  3. Cleanup:           ./scripts/cleanup.sh"
echo ""
