#!/bin/bash
# Deploy script: Apply Kubernetes manifests to kind cluster
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

SCENARIO_DIR="$(get_scenario_dir)"
PROJECT_ROOT="$(get_project_root)"

# Parse arguments
WITH_METRICS=false
WITH_INGRESS=false
WITH_HPA=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --with-metrics)
            WITH_METRICS=true
            shift
            ;;
        --with-ingress)
            WITH_INGRESS=true
            shift
            ;;
        --with-hpa)
            WITH_HPA=true
            WITH_METRICS=true  # HPA requires metrics
            shift
            ;;
        --all)
            WITH_METRICS=true
            WITH_INGRESS=true
            WITH_HPA=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Usage: $0 [--with-metrics] [--with-ingress] [--with-hpa] [--all]"
            exit 1
            ;;
    esac
done

echo ""
echo "=========================================="
echo "Kubernetes Test Scenario - Deploy"
echo "=========================================="
echo ""

# Check if cluster exists
if ! cluster_exists; then
    log_error "Kind cluster '$CLUSTER_NAME' does not exist. Run setup.sh first."
    exit 1
fi

# Ensure correct context
kubectl config use-context "kind-${CLUSTER_NAME}" &>/dev/null

# Step 1: Create namespace
log_step "Creating namespace..."
kubectl apply -f "${PROJECT_ROOT}/kubernetes/base/namespace.yaml"
log_success "Namespace created"

# Step 2: Create ConfigMap from local config files
log_step "Creating ConfigMap from local config files..."
kubectl create configmap webhook-config \
    --from-file=webhooks.json="${SCENARIO_DIR}/config/webhooks.json" \
    --from-file=connections.json="${SCENARIO_DIR}/config/connections.json" \
    -n "$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -
log_success "ConfigMap created"

# Step 3: Apply secrets
log_step "Applying secrets..."
kubectl apply -f "${SCENARIO_DIR}/patches/secret-local.yaml"
log_success "Secrets applied"

# Step 4: Apply base service
log_step "Applying service..."
kubectl apply -f "${PROJECT_ROOT}/kubernetes/base/service.yaml"
log_success "Service applied"

# Step 5: Create patched deployment (apply base then patch)
log_step "Deploying application with local patches..."

# Apply base deployment first
kubectl apply -f "${PROJECT_ROOT}/kubernetes/base/deployment.yaml"

# Now patch for local testing:
# - Change image to local
# - Set imagePullPolicy to Never
# - Reduce replicas to 1
# Note: /tmp volume NOT needed - PYTHONDONTWRITEBYTECODE=1 and no temp file usage
kubectl patch deployment webhook-deployment -n "$NAMESPACE" --type='json' -p='[
  {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "webhook-module:local"},
  {"op": "replace", "path": "/spec/template/spec/containers/0/imagePullPolicy", "value": "Never"},
  {"op": "replace", "path": "/spec/replicas", "value": 1}
]'
log_success "Application deployed"

# Step 6: Wait for deployment
wait_for_deployment "webhook-deployment" "$NAMESPACE" 120

# Step 7: Install metrics-server if requested
if [ "$WITH_METRICS" = true ]; then
    log_step "Installing metrics-server..."
    kubectl apply -f "${SCENARIO_DIR}/addons/metrics-server.yaml"
    wait_for_deployment "metrics-server" "kube-system" 120
    log_success "Metrics-server installed"
fi

# Step 8: Install HPA if requested
if [ "$WITH_HPA" = true ]; then
    log_step "Applying HPA..."
    kubectl apply -f "${PROJECT_ROOT}/kubernetes/base/hpa.yaml"
    log_success "HPA applied"
fi

# Step 9: Install ingress controller if requested
if [ "$WITH_INGRESS" = true ]; then
    log_step "Installing nginx-ingress controller..."
    "${SCENARIO_DIR}/addons/install-ingress-nginx.sh"

    log_step "Applying ingress resource..."
    kubectl apply -f "${PROJECT_ROOT}/kubernetes/optional/ingress-nginx.yaml"
    log_success "Ingress configured"
fi

# Show status
echo ""
echo "=========================================="
log_success "Deployment complete!"
echo "=========================================="
echo ""

log_step "Deployment status:"
kubectl get pods -n "$NAMESPACE"

echo ""
log_step "Services:"
kubectl get svc -n "$NAMESPACE"

if [ "$WITH_HPA" = true ]; then
    echo ""
    log_step "HPA status:"
    kubectl get hpa -n "$NAMESPACE"
fi

if [ "$WITH_INGRESS" = true ]; then
    echo ""
    log_step "Ingress status:"
    kubectl get ingress -n "$NAMESPACE"
fi

echo ""
echo "Next steps:"
echo "  Run tests:    ./scripts/test.sh [basic|scaling|ingress|all]"
echo "  View logs:    kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=core-webhook-module -f"
echo "  Port forward: kubectl port-forward -n $NAMESPACE svc/webhook-service 8000:80"
echo ""
