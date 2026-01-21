# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the Core Webhook Module.

## Directory Structure

```
kubernetes/
├── README.md                        # This file
├── base/
│   ├── namespace.yaml               # webhook-system namespace
│   ├── configmap.yaml               # webhooks.json + connections.json
│   ├── secret.yaml                  # Auth tokens (template)
│   ├── deployment.yaml              # Main app deployment
│   ├── service.yaml                 # ClusterIP service
│   └── hpa.yaml                     # Horizontal Pod Autoscaler
└── optional/
    ├── service-loadbalancer.yaml    # LoadBalancer variant
    ├── ingress-nginx.yaml           # Nginx Ingress example
    └── networkpolicy.yaml           # Network isolation
```

## Quick Start

### 1. Configure Secrets

Edit `base/secret.yaml` and replace the placeholder values:

```yaml
stringData:
  STATS_AUTH_TOKEN: "your-actual-stats-token"
  CONFIG_RELOAD_ADMIN_TOKEN: "your-actual-admin-token"
```

### 2. Configure Container Image

Edit `base/deployment.yaml` and update the image:

```yaml
image: ghcr.io/YOUR_ORG/core-webhook-module:latest
```

### 3. Deploy Base Resources

```bash
kubectl apply -f kubernetes/base/
```

### 4. Verify Deployment

```bash
# Check resources
kubectl -n webhook-system get pods,svc,hpa

# Check pod logs
kubectl -n webhook-system logs -l app.kubernetes.io/name=core-webhook-module

# Port forward for local testing
kubectl -n webhook-system port-forward svc/webhook-service 8000:80
```

### 5. Test the Deployment

```bash
# Health check
curl http://localhost:8000/health

# Test webhook
curl -X POST http://localhost:8000/webhook/example \
  -H "Authorization: Bearer test" \
  -H "Content-Type: application/json" \
  -d '{"test": true}'
```

## Configuration

### Webhook Configuration

Edit `base/configmap.yaml` to add your webhooks:

```yaml
data:
  webhooks.json: |
    {
      "my-webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer my-secret-token",
        "module-config": {
          "pretty_print": true
        }
      }
    }
  connections.json: |
    {
      "my-redis": {
        "type": "redis",
        "host": "redis-service.default.svc.cluster.local",
        "port": 6379
      }
    }
```

After updating the ConfigMap, restart the pods to pick up changes:

```bash
kubectl -n webhook-system rollout restart deployment/webhook-deployment
```

### Environment Variables

| Variable | Description | Source |
|----------|-------------|--------|
| `WEBHOOKS_CONFIG_FILE` | Path to webhooks.json | Deployment env |
| `CONNECTIONS_CONFIG_FILE` | Path to connections.json | Deployment env |
| `STATS_AUTH_TOKEN` | Token for /stats endpoint | Secret |
| `CONFIG_RELOAD_ADMIN_TOKEN` | Token for /admin/reload-config | Secret |

## Optional Components

### LoadBalancer Service

For cloud providers with LoadBalancer support:

```bash
kubectl apply -f kubernetes/optional/service-loadbalancer.yaml
```

Uncomment the appropriate cloud provider annotations in the file.

### Nginx Ingress

For HTTP(S) ingress with TLS:

1. Edit `optional/ingress-nginx.yaml` and update the host
2. Uncomment TLS section if using HTTPS
3. Apply:

```bash
kubectl apply -f kubernetes/optional/ingress-nginx.yaml
```

### Network Policy

For network isolation (requires CNI with NetworkPolicy support):

```bash
kubectl apply -f kubernetes/optional/networkpolicy.yaml
```

This policy:
- Allows ingress from ingress-nginx namespace
- Allows DNS egress
- Allows HTTPS/HTTP egress to external IPs only

## Resource Defaults

| Setting | Value |
|---------|-------|
| Replicas | 2 (min), 10 (max) |
| Memory | 128Mi (request), 512Mi (limit) |
| CPU | 100m (request), 500m (limit) |
| Container Port | 8000 |
| Service Port | 80 |
| Health Endpoint | /health |

## Scaling

The HPA automatically scales based on:
- CPU utilization > 70%
- Memory utilization > 80%

Manual scaling:

```bash
kubectl -n webhook-system scale deployment/webhook-deployment --replicas=5
```

## Troubleshooting

### Pods not starting

```bash
# Check pod status
kubectl -n webhook-system describe pod -l app.kubernetes.io/name=core-webhook-module

# Check events
kubectl -n webhook-system get events --sort-by='.lastTimestamp'
```

### Health check failing

```bash
# Check if container is running
kubectl -n webhook-system exec -it deploy/webhook-deployment -- curl localhost:8000/health
```

### View logs

```bash
# All pods
kubectl -n webhook-system logs -l app.kubernetes.io/name=core-webhook-module --tail=100

# Single pod
kubectl -n webhook-system logs <pod-name> -f
```

## Cleanup

Remove all resources:

```bash
kubectl delete -f kubernetes/optional/  # Optional components first
kubectl delete -f kubernetes/base/
```
