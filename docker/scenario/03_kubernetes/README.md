# Kubernetes Local Testing Scenario

This scenario provides a standalone local Kubernetes testing environment using **kind (Kubernetes IN Docker)** to validate all manifests in `kubernetes/base/` and `kubernetes/optional/`.

## Overview

The test scenario:
1. Creates a local Kubernetes cluster using kind
2. Builds and loads the webhook Docker image
3. Deploys manifests using kustomize patches for local testing
4. Validates webhook functionality through automated tests

## Prerequisites

- **Docker** - Running and accessible
- **kind** - Kubernetes IN Docker ([installation](https://kind.sigs.k8s.io/docs/user/quick-start/#installation))
- **kubectl** - Kubernetes CLI ([installation](https://kubernetes.io/docs/tasks/tools/))

### Installing Prerequisites

```bash
# macOS with Homebrew
brew install kind kubectl

# Linux
# kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

## Quick Start

```bash
cd docker/scenario/03_kubernetes

# Run basic test (creates cluster, builds image, deploys, tests)
./run_test.sh basic

# Or use make
make all
```

## Directory Structure

```
docker/scenario/03_kubernetes/
├── README.md                       # This documentation
├── .gitignore                      # Ignore logs, kubeconfig
├── Makefile                        # Simple make commands
├── run_test.sh                     # Main orchestration script
├── scripts/
│   ├── setup.sh                    # Create kind cluster, build/load image
│   ├── deploy.sh                   # Deploy manifests to cluster
│   ├── test.sh                     # Send webhooks, verify responses
│   ├── cleanup.sh                  # Delete cluster and cleanup
│   └── utils.sh                    # Shared utility functions
├── config/
│   ├── kind-cluster.yaml           # kind cluster configuration
│   ├── webhooks.json               # Test webhook configuration
│   └── connections.json            # Empty connections config
├── patches/
│   ├── kustomization.yaml          # Kustomize overlay
│   └── secret-local.yaml           # Local test secrets
├── addons/
│   ├── metrics-server.yaml         # Metrics server for HPA testing
│   └── install-ingress-nginx.sh    # Install nginx ingress controller
└── logs/
    └── .gitkeep
```

## Usage

### Quick Commands (Makefile)

```bash
make setup          # Create kind cluster and build/load image
make deploy         # Deploy manifests to cluster
make test           # Run basic tests
make test-scaling   # Run scaling tests (includes HPA)
make test-ingress   # Run ingress tests
make test-all       # Run all tests
make clean          # Delete kind cluster
make status         # Show cluster status
make logs           # Show pod logs
make port-forward   # Start port forwarding
```

### Manual Step-by-Step

#### 1. Setup Cluster

```bash
./scripts/setup.sh
```

This will:
- Check prerequisites (docker, kind, kubectl)
- Create a kind cluster with port mappings
- Build the Docker image from project root
- Load the image into the kind cluster

#### 2. Deploy Application

```bash
# Basic deployment
./scripts/deploy.sh

# With HPA (requires metrics-server)
./scripts/deploy.sh --with-hpa

# With Ingress
./scripts/deploy.sh --with-ingress

# All features
./scripts/deploy.sh --all
```

#### 3. Run Tests

```bash
# Basic connectivity tests
./scripts/test.sh basic

# HPA scaling tests
./scripts/test.sh scaling

# Ingress routing tests
./scripts/test.sh ingress

# All tests
./scripts/test.sh all
```

#### 4. Cleanup

```bash
# Delete cluster (with confirmation)
./scripts/cleanup.sh

# Delete cluster without confirmation
./scripts/cleanup.sh --force

# Also clean log files
./scripts/cleanup.sh --force --logs
```

## Test Scenarios

### Basic Test

Validates core functionality:
- Pod is running and healthy
- `/health` endpoint returns 200
- `/` root endpoint returns 200
- Webhook endpoint accepts and processes requests
- Pod logs show received webhooks

### Scaling Test

Validates HPA functionality:
- Metrics-server is installed and providing metrics
- HPA is configured and targeting deployment
- `kubectl top pods` returns metrics
- Load generation triggers scaling (may take several minutes)

### Ingress Test

Validates ingress routing:
- nginx-ingress controller is installed
- Ingress resource is configured
- Requests via `Host: webhook.example.com` are routed correctly
- Health and webhook endpoints accessible via ingress

## Configuration

### Webhook Configuration

The test uses a simple webhook config (`config/webhooks.json`):

```json
{
  "test": {
    "data_type": "json",
    "module": "log",
    "authorization": "Bearer test_token_123"
  }
}
```

### Kustomize Patches

The `patches/kustomization.yaml` applies these changes to base manifests:
- Image: `webhook-module:local` (locally built)
- `imagePullPolicy: Never` (use local image)
- Adds `/tmp` emptyDir volume (required for readOnlyRootFilesystem)
- Reduces replicas to 1 for local testing

### Kind Cluster

Port mappings in `config/kind-cluster.yaml`:
- `18080` → Ingress HTTP (port 80)
- `18443` → Ingress HTTPS (port 443)
- `30080` → NodePort access

## Troubleshooting

### Cluster won't start

```bash
# Check Docker is running
docker info

# Check for existing cluster
kind get clusters

# Delete stuck cluster
kind delete cluster --name webhook-test
```

### Image not found

```bash
# Rebuild and reload image
cd /path/to/project/root
docker build -t webhook-module:local -f docker/Dockerfile.smaller .
kind load docker-image webhook-module:local --name webhook-test
```

### Pod in CrashLoopBackOff

```bash
# Check pod status
kubectl describe pod -n webhook-system -l app.kubernetes.io/name=core-webhook-module

# Check logs
kubectl logs -n webhook-system -l app.kubernetes.io/name=core-webhook-module --previous
```

### Port forward not working

```bash
# Kill existing port forwards
pkill -f "kubectl port-forward"

# Start fresh
kubectl port-forward -n webhook-system svc/webhook-service 8000:80
```

### Metrics not available for HPA

```bash
# Check metrics-server is running
kubectl get pods -n kube-system | grep metrics-server

# Check metrics-server logs
kubectl logs -n kube-system -l k8s-app=metrics-server

# Wait for metrics (can take 1-2 minutes after deployment)
kubectl top pods -n webhook-system
```

### Ingress not routing requests

```bash
# Check ingress controller is running
kubectl get pods -n ingress-nginx

# Check ingress resource
kubectl describe ingress -n webhook-system webhook-ingress

# Test with verbose curl
curl -v -H "Host: webhook.example.com" http://localhost:18080/health
```

## Manifest Handling for Local Testing

| Issue | Problem | Solution |
|-------|---------|----------|
| Image placeholder | `ghcr.io/YOUR_ORG/...` doesn't exist | kubectl patch: use `webhook-module:local` with `imagePullPolicy: Never` |
| HPA needs metrics | metrics-server not included | Add `addons/metrics-server.yaml` with `--kubelet-insecure-tls` |
| Ingress needs controller | nginx-ingress not installed | Add `install-ingress-nginx.sh` script |

**Note:** `readOnlyRootFilesystem: true` works without `/tmp` volume because `PYTHONDONTWRITEBYTECODE=1` is set in the Dockerfile.

## Useful Commands

```bash
# Watch pods
kubectl get pods -n webhook-system -w

# Get all resources
kubectl get all -n webhook-system

# Describe deployment
kubectl describe deployment -n webhook-system webhook-deployment

# Shell into pod
kubectl exec -it -n webhook-system deploy/webhook-deployment -- /bin/sh

# View configmap
kubectl get configmap -n webhook-system webhook-config -o yaml

# Check events
kubectl get events -n webhook-system --sort-by='.lastTimestamp'
```

## Notes

- The kind cluster persists between test runs. Use `cleanup.sh` to remove it.
- Image rebuilds require reloading into kind (`kind load docker-image`)
- HPA scaling can take several minutes to trigger based on metrics collection interval
- Ingress requires the nginx controller to be fully ready before routing works
