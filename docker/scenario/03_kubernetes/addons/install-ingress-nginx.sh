#!/bin/bash
# Install nginx-ingress controller for kind cluster
# This uses the kind-specific manifest from the official ingress-nginx repo
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../scripts/utils.sh"

log_step "Installing nginx-ingress controller for kind..."

# Apply the official kind-compatible nginx-ingress manifest
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# Wait for the ingress controller to be ready
log_step "Waiting for ingress-nginx controller to be ready..."

# Wait for namespace to be created
sleep 5

# Wait for deployment
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=120s

log_success "nginx-ingress controller installed and ready"
