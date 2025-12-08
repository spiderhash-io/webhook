# Rolling Config Update Feature for Kubernetes

## Overview

This document describes how to implement rolling configuration updates for the Core Webhook Module in a Kubernetes cluster. Kubernetes provides native features for rolling updates, health checks, and load balancing that simplify the implementation compared to Docker Compose deployments.

## Architecture

### Kubernetes Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Centralized Management UI                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Kubernetes API Client                                 │  │
│  │  - Update ConfigMaps                                    │  │
│  │  - Trigger rolling updates                              │  │
│  │  - Monitor pod status                                   │  │
│  └───────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
              ┌────────────────────┐
              │  Kubernetes API    │
              └─────────┬──────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  Deployment  │ │  Deployment  │ │  Deployment  │
│  (ReplicaSet)│ │  (ReplicaSet)│ │  (ReplicaSet)│
│              │ │              │ │              │
│  Pod 1       │ │  Pod 2       │ │  Pod 3       │
│  Pod 4       │ │  Pod 5       │ │  Pod 6       │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                 │
       └────────────────┼─────────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │  Service (LB)     │
              │  (Load Balancer)  │
              └──────────────────┘
                        │
                        ▼
              External Traffic
```

### Key Kubernetes Features Used

1. **Deployments**: Manage pod replicas and rolling updates
2. **ConfigMaps**: Store configuration data
3. **Secrets**: Store sensitive configuration
4. **Services**: Provide load balancing and service discovery
5. **Readiness/Liveness Probes**: Health checks for pods
6. **PodDisruptionBudgets**: Control availability during updates
7. **Rolling Update Strategy**: Zero-downtime updates

## Implementation Approaches

### Approach 1: ConfigMap-Based (Recommended for Static Config)

Use Kubernetes ConfigMaps to store configuration and trigger rolling updates when config changes.

#### Step 1: Create ConfigMap

**File**: `k8s/configmap-webhooks.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: webhook-config
  namespace: webhook-system
data:
  webhooks.json: |
    {
      "webhook_id": {
        "module": "rabbitmq",
        "connection": "rabbitmq_prod",
        "authorization": "Bearer {$WEBHOOK_SECRET}"
      }
    }
  connections.json: |
    {
      "rabbitmq_prod": {
        "type": "rabbitmq",
        "host": "{$RABBITMQ_HOST}",
        "port": 5672,
        "user": "guest",
        "pass": "guest"
      }
    }
```

**Apply ConfigMap**:

```bash
kubectl apply -f k8s/configmap-webhooks.yaml
```

#### Step 2: Create Deployment with ConfigMap Mount

**File**: `k8s/deployment.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-deployment
  namespace: webhook-system
  labels:
    app: webhook
spec:
  replicas: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1          # Add 1 pod at a time
      maxUnavailable: 0     # Keep all pods available (zero downtime)
  selector:
    matchLabels:
      app: webhook
  template:
    metadata:
      labels:
        app: webhook
    spec:
      containers:
      - name: webhook
        image: core-webhook-module:latest
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8000
          protocol: TCP
        env:
        - name: REDIS_HOST
          value: "redis-service"
        - name: RABBITMQ_HOST
          value: "rabbitmq-service"
        - name: CLICKHOUSE_HOST
          value: "clickhouse-service"
        - name: INSTANCE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: CONFIG_RELOAD_ADMIN_TOKEN
          valueFrom:
            secretKeyRef:
              name: webhook-secrets
              key: CONFIG_RELOAD_ADMIN_TOKEN
        volumeMounts:
        - name: config
          mountPath: /app/webhooks.json
          subPath: webhooks.json
          readOnly: true
        - name: config
          mountPath: /app/connections.json
          subPath: connections.json
          readOnly: true
        # Health probes
        livenessProbe:
          httpGet:
            path: /admin/health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /admin/health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: webhook-config
```

**Apply Deployment**:

```bash
kubectl apply -f k8s/deployment.yaml
```

#### Step 3: Create Service for Load Balancing

**File**: `k8s/service.yaml`

```yaml
apiVersion: v1
kind: Service
metadata:
  name: webhook-service
  namespace: webhook-system
  labels:
    app: webhook
spec:
  type: LoadBalancer  # Use ClusterIP for internal only, NodePort for specific ports
  selector:
    app: webhook
  ports:
  - name: http
    port: 80
    targetPort: 8000
    protocol: TCP
  sessionAffinity: None  # Round-robin load balancing
```

**Apply Service**:

```bash
kubectl apply -f k8s/service.yaml
```

#### Step 4: Create Secret for Admin Token

**File**: `k8s/secret.yaml`

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: webhook-secrets
  namespace: webhook-system
type: Opaque
stringData:
  CONFIG_RELOAD_ADMIN_TOKEN: "your-secret-admin-token-here"
  WEBHOOK_SECRET: "webhook-secret-value"
```

**Apply Secret**:

```bash
kubectl apply -f k8s/secret.yaml
```

#### Step 5: Rolling Update Process

**Update ConfigMap**:

```bash
# Method 1: Update from file
kubectl create configmap webhook-config \
  --from-file=webhooks.json=./webhooks.json \
  --from-file=connections.json=./connections.json \
  --namespace=webhook-system \
  --dry-run=client -o yaml | kubectl apply -f -

# Method 2: Edit directly
kubectl edit configmap webhook-config -n webhook-system
```

**Trigger Rolling Update**:

```bash
# Method 1: Update deployment annotation (recommended)
kubectl patch deployment webhook-deployment \
  -n webhook-system \
  -p '{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"'$(date +%s)'"}}}}}'

# Method 2: Update image tag
kubectl set image deployment/webhook-deployment \
  webhook=core-webhook-module:latest \
  -n webhook-system

# Method 3: Scale down and up (not recommended)
kubectl scale deployment webhook-deployment --replicas=4 -n webhook-system
kubectl scale deployment webhook-deployment --replicas=5 -n webhook-system
```

**Monitor Rolling Update**:

```bash
# Watch rollout status
kubectl rollout status deployment/webhook-deployment -n webhook-system

# Watch pods being updated
kubectl get pods -n webhook-system -w

# Check deployment status
kubectl get deployment webhook-deployment -n webhook-system

# View rollout history
kubectl rollout history deployment/webhook-deployment -n webhook-system
```

**Rollback if Needed**:

```bash
# Rollback to previous version
kubectl rollout undo deployment/webhook-deployment -n webhook-system

# Rollback to specific revision
kubectl rollout undo deployment/webhook-deployment --to-revision=2 -n webhook-system
```

### Approach 2: Push-Based with Kubernetes API

Update ConfigMaps programmatically and trigger rolling updates via the Kubernetes API.

#### Python Script for Kubernetes Rolling Update

**File**: `k8s/rolling_update.py`

```python
"""
Kubernetes Rolling Update Script

This script updates ConfigMaps and triggers rolling updates
for webhook deployments in Kubernetes.
"""
import kubernetes
from kubernetes import client, config
import json
import time
import sys
from typing import Dict, Any, Optional


class KubernetesRollingUpdater:
    """Manages rolling updates for webhook deployments in Kubernetes."""
    
    def __init__(self, namespace: str = "webhook-system"):
        """
        Initialize Kubernetes client.
        
        Args:
            namespace: Kubernetes namespace for webhook deployment
        """
        try:
            # Try in-cluster config first (for pods running in cluster)
            config.load_incluster_config()
        except config.ConfigException:
            # Fall back to kubeconfig (for local development)
            config.load_kube_config()
        
        self.namespace = namespace
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
    
    def update_configmap(
        self,
        configmap_name: str,
        webhooks_data: Dict[str, Any],
        connections_data: Dict[str, Any]
    ) -> bool:
        """
        Update ConfigMap with new configuration.
        
        Args:
            configmap_name: Name of the ConfigMap
            webhooks_data: Webhook configuration dictionary
            connections_data: Connection configuration dictionary
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get existing ConfigMap
            cm = self.core_v1.read_namespaced_config_map(
                name=configmap_name,
                namespace=self.namespace
            )
            
            # Update data
            cm.data["webhooks.json"] = json.dumps(webhooks_data, indent=2)
            cm.data["connections.json"] = json.dumps(connections_data, indent=2)
            
            # Apply update
            self.core_v1.patch_namespaced_config_map(
                name=configmap_name,
                namespace=self.namespace,
                body=cm
            )
            
            print(f"✓ ConfigMap '{configmap_name}' updated")
            return True
        except client.exceptions.ApiException as e:
            print(f"✗ Failed to update ConfigMap: {e.reason} - {e.body}")
            return False
        except Exception as e:
            print(f"✗ Failed to update ConfigMap: {e}")
            return False
    
    def trigger_rolling_update(self, deployment_name: str) -> bool:
        """
        Trigger rolling update by updating deployment annotation.
        
        Args:
            deployment_name: Name of the Deployment
        
        Returns:
            True if successful, False otherwise
        """
        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace
            )
            
            # Add restart annotation to trigger rolling update
            if deployment.spec.template.metadata.annotations is None:
                deployment.spec.template.metadata.annotations = {}
            
            deployment.spec.template.metadata.annotations[
                "kubectl.kubernetes.io/restartedAt"
            ] = str(int(time.time()))
            
            self.apps_v1.patch_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace,
                body=deployment
            )
            
            print(f"✓ Rolling update triggered for '{deployment_name}'")
            return True
        except client.exceptions.ApiException as e:
            print(f"✗ Failed to trigger rolling update: {e.reason} - {e.body}")
            return False
        except Exception as e:
            print(f"✗ Failed to trigger rolling update: {e}")
            return False
    
    def wait_for_rollout(
        self,
        deployment_name: str,
        timeout: int = 300
    ) -> bool:
        """
        Wait for deployment rollout to complete.
        
        Args:
            deployment_name: Name of the Deployment
            timeout: Maximum time to wait in seconds
        
        Returns:
            True if rollout completed successfully, False otherwise
        """
        try:
            watch = kubernetes.watch.Watch()
            start_time = time.time()
            
            print(f"Waiting for rollout of '{deployment_name}'...")
            
            for event in watch.stream(
                func=self.apps_v1.list_namespaced_deployment,
                namespace=self.namespace,
                timeout_seconds=timeout
            ):
                if time.time() - start_time > timeout:
                    print("✗ Rollout timeout exceeded")
                    return False
                
                deployment = event['object']
                if deployment.metadata.name == deployment_name:
                    status = deployment.status
                    
                    # Check if rollout is complete
                    if (status.updated_replicas == status.replicas and
                        status.available_replicas == status.replicas and
                        status.ready_replicas == status.replicas):
                        print(f"✓ Deployment '{deployment_name}' rollout complete")
                        watch.stop()
                        return True
                    
                    # Print progress
                    print(
                        f"  Progress: {status.ready_replicas}/{status.replicas} "
                        f"pods ready (updated: {status.updated_replicas})"
                    )
            
            print("✗ Rollout did not complete within timeout")
            return False
        except Exception as e:
            print(f"✗ Rollout failed: {e}")
            return False
    
    def get_pod_status(self, deployment_name: str) -> Dict[str, Any]:
        """
        Get status of all pods in deployment.
        
        Args:
            deployment_name: Name of the Deployment
        
        Returns:
            Dictionary with pod status information
        """
        try:
            pods = self.core_v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=f"app={deployment_name}"
            )
            
            status = {
                "total": len(pods.items),
                "ready": 0,
                "not_ready": 0,
                "pods": []
            }
            
            for pod in pods.items:
                is_ready = any(
                    condition.type == "Ready" and condition.status == "True"
                    for condition in pod.status.conditions or []
                )
                
                if is_ready:
                    status["ready"] += 1
                else:
                    status["not_ready"] += 1
                
                status["pods"].append({
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "ready": is_ready,
                    "ip": pod.status.pod_ip
                })
            
            return status
        except Exception as e:
            print(f"✗ Failed to get pod status: {e}")
            return {"error": str(e)}
    
    def rollback_deployment(
        self,
        deployment_name: str,
        revision: Optional[int] = None
    ) -> bool:
        """
        Rollback deployment to previous or specific revision.
        
        Args:
            deployment_name: Name of the Deployment
            revision: Specific revision number (None for previous)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if revision is None:
                # Rollback to previous revision
                self.apps_v1.create_namespaced_deployment_rollback(
                    name=deployment_name,
                    namespace=self.namespace,
                    body=client.V1DeploymentRollback(
                        name=deployment_name,
                        rollback_to=client.V1RollbackConfig(revision=0)
                    )
                )
                print(f"✓ Rolled back '{deployment_name}' to previous revision")
            else:
                # Rollback to specific revision
                self.apps_v1.create_namespaced_deployment_rollback(
                    name=deployment_name,
                    namespace=self.namespace,
                    body=client.V1DeploymentRollback(
                        name=deployment_name,
                        rollback_to=client.V1RollbackConfig(revision=revision)
                    )
                )
                print(f"✓ Rolled back '{deployment_name}' to revision {revision}")
            
            return True
        except Exception as e:
            print(f"✗ Failed to rollback: {e}")
            return False


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Kubernetes Rolling Update Tool")
    parser.add_argument(
        "--namespace",
        default="webhook-system",
        help="Kubernetes namespace"
    )
    parser.add_argument(
        "--deployment",
        default="webhook-deployment",
        help="Deployment name"
    )
    parser.add_argument(
        "--configmap",
        default="webhook-config",
        help="ConfigMap name"
    )
    parser.add_argument(
        "--webhooks-file",
        required=True,
        help="Path to webhooks.json file"
    )
    parser.add_argument(
        "--connections-file",
        required=True,
        help="Path to connections.json file"
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for rollout to complete"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show pod status only"
    )
    parser.add_argument(
        "--rollback",
        type=int,
        metavar="REVISION",
        help="Rollback to specific revision (omit for previous)"
    )
    
    args = parser.parse_args()
    
    updater = KubernetesRollingUpdater(namespace=args.namespace)
    
    # Handle rollback
    if args.rollback is not None:
        updater.rollback_deployment(args.deployment, args.rollback)
        return
    
    # Handle status check
    if args.status:
        status = updater.get_pod_status(args.deployment)
        print(f"\nPod Status:")
        print(f"  Total: {status['total']}")
        print(f"  Ready: {status['ready']}")
        print(f"  Not Ready: {status['not_ready']}")
        print(f"\nPods:")
        for pod in status['pods']:
            print(f"  {pod['name']}: {pod['status']} (ready: {pod['ready']})")
        return
    
    # Load configuration files
    try:
        with open(args.webhooks_file) as f:
            webhooks = json.load(f)
        with open(args.connections_file) as f:
            connections = json.load(f)
    except FileNotFoundError as e:
        print(f"✗ File not found: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)
    
    # Update ConfigMap
    if not updater.update_configmap(args.configmap, webhooks, connections):
        sys.exit(1)
    
    # Trigger rolling update
    if not updater.trigger_rolling_update(args.deployment):
        sys.exit(1)
    
    # Wait for completion if requested
    if args.wait:
        if not updater.wait_for_rollout(args.deployment):
            sys.exit(1)
    
    # Show final status
    status = updater.get_pod_status(args.deployment)
    print(f"\nFinal Status: {status['ready']}/{status['total']} pods ready")


if __name__ == "__main__":
    main()
```

**Usage**:

```bash
# Install Kubernetes Python client
pip install kubernetes

# Update config and trigger rolling update
python k8s/rolling_update.py \
  --webhooks-file webhooks.json \
  --connections-file connections.json \
  --wait

# Check status only
python k8s/rolling_update.py --status

# Rollback to previous revision
python k8s/rolling_update.py --rollback

# Rollback to specific revision
python k8s/rolling_update.py --rollback 2
```

### Approach 3: Hybrid - ConfigMap + Push API

Use ConfigMaps for initial config and push API for runtime updates without pod restarts.

**Deployment with writable volume**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-deployment
spec:
  template:
    spec:
      containers:
      - name: webhook
        volumeMounts:
        - name: config
          mountPath: /app/config
          # NOT readOnly - allows runtime updates
      volumes:
      - name: config
        configMap:
          name: webhook-config
          # Or use emptyDir for runtime-only updates
          # emptyDir: {}
```

**Update flow**:

1. Update ConfigMap (for new pods)
2. Push config to existing pods via `/admin/config-update` API
3. Kubernetes handles pod rotation naturally

**Hybrid update script**:

```python
def hybrid_update(updater, webhooks, connections, deployment_name):
    """Update both ConfigMap and existing pods."""
    # 1. Update ConfigMap (for new pods)
    updater.update_configmap("webhook-config", webhooks, connections)
    
    # 2. Push to existing pods
    pods = updater.core_v1.list_namespaced_pod(
        namespace="webhook-system",
        label_selector="app=webhook"
    )
    
    admin_token = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN")
    
    for pod in pods.items:
        pod_ip = pod.status.pod_ip
        # Push config via API
        push_config_to_pod(
            f"http://{pod_ip}:8000",
            webhooks,
            connections,
            admin_token
        )
    
    # 3. Trigger rolling update (gradual replacement)
    updater.trigger_rolling_update(deployment_name)
```

## Advanced Kubernetes Features

### 1. PodDisruptionBudget

Control how many pods can be unavailable during updates:

**File**: `k8s/pod-disruption-budget.yaml`

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: webhook-pdb
  namespace: webhook-system
spec:
  minAvailable: 4  # At least 4 pods must be available
  # Or use maxUnavailable instead:
  # maxUnavailable: 1
  selector:
    matchLabels:
      app: webhook
```

**Apply**:

```bash
kubectl apply -f k8s/pod-disruption-budget.yaml
```

### 2. HorizontalPodAutoscaler

Scale based on load:

**File**: `k8s/hpa.yaml`

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: webhook-hpa
  namespace: webhook-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: webhook-deployment
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 2
        periodSeconds: 15
      selectPolicy: Max
```

**Apply**:

```bash
kubectl apply -f k8s/hpa.yaml
```

### 3. Init Container for Config Validation

Validate config before main container starts:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-deployment
spec:
  template:
    spec:
      initContainers:
      - name: config-validator
        image: config-validator:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          echo "Validating configuration..."
          python -m json.tool /app/config/webhooks.json > /dev/null
          python -m json.tool /app/config/connections.json > /dev/null
          echo "Configuration valid"
        volumeMounts:
        - name: config
          mountPath: /app/config
      containers:
      - name: webhook
        # ... main container config
```

### 4. Readiness Gate

Use custom conditions for readiness:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-deployment
spec:
  template:
    spec:
      containers:
      - name: webhook
        readinessGates:
        - conditionType: ConfigReady
        # ... rest of config
```

## Complete Kubernetes Setup

**File**: `k8s/complete-setup.yaml`

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: webhook-system

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: webhook-config
  namespace: webhook-system
data:
  webhooks.json: |
    {
      "webhook_id": {
        "module": "rabbitmq",
        "connection": "rabbitmq_prod"
      }
    }
  connections.json: |
    {
      "rabbitmq_prod": {
        "type": "rabbitmq",
        "host": "rabbitmq-service",
        "port": 5672
      }
    }

---
apiVersion: v1
kind: Secret
metadata:
  name: webhook-secrets
  namespace: webhook-system
type: Opaque
stringData:
  CONFIG_RELOAD_ADMIN_TOKEN: "your-secret-token-here"
  WEBHOOK_SECRET: "webhook-secret-value"

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-deployment
  namespace: webhook-system
  labels:
    app: webhook
spec:
  replicas: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: webhook
  template:
    metadata:
      labels:
        app: webhook
    spec:
      containers:
      - name: webhook
        image: core-webhook-module:latest
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8000
        env:
        - name: REDIS_HOST
          value: "redis-service"
        - name: RABBITMQ_HOST
          value: "rabbitmq-service"
        - name: CLICKHOUSE_HOST
          value: "clickhouse-service"
        - name: INSTANCE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: CONFIG_RELOAD_ADMIN_TOKEN
          valueFrom:
            secretKeyRef:
              name: webhook-secrets
              key: CONFIG_RELOAD_ADMIN_TOKEN
        volumeMounts:
        - name: config
          mountPath: /app/webhooks.json
          subPath: webhooks.json
          readOnly: true
        - name: config
          mountPath: /app/connections.json
          subPath: connections.json
          readOnly: true
        livenessProbe:
          httpGet:
            path: /admin/health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /admin/health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: webhook-config

---
apiVersion: v1
kind: Service
metadata:
  name: webhook-service
  namespace: webhook-system
  labels:
    app: webhook
spec:
  type: LoadBalancer
  selector:
    app: webhook
  ports:
  - name: http
    port: 80
    targetPort: 8000
    protocol: TCP

---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: webhook-pdb
  namespace: webhook-system
spec:
  minAvailable: 4
  selector:
    matchLabels:
      app: webhook

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: webhook-hpa
  namespace: webhook-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: webhook-deployment
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

**Apply complete setup**:

```bash
kubectl apply -f k8s/complete-setup.yaml
```

## Comparison: Docker Compose vs Kubernetes

| Feature | Docker Compose | Kubernetes |
|---------|----------------|------------|
| **Load Balancing** | Manual (Nginx) | Native (Service) |
| **Health Checks** | Manual scripts | Native (Probes) |
| **Rolling Updates** | Manual script | Native (Deployment) |
| **Config Management** | File mounts | ConfigMaps/Secrets |
| **Service Discovery** | Manual | Native (DNS) |
| **Scaling** | Manual | Native (HPA) |
| **Zero Downtime** | Script-based | Built-in |
| **Rollback** | Manual | `kubectl rollout undo` |
| **Self-Healing** | Manual | Automatic |
| **Resource Limits** | Manual | Native (Resources) |

## Benefits of Kubernetes Approach

1. **Native Rolling Updates**: No custom scripts needed - Kubernetes handles it automatically
2. **Automatic Health Checks**: Readiness/liveness probes ensure only healthy pods receive traffic
3. **Built-in Load Balancing**: Service provides automatic load balancing across pods
4. **Config Versioning**: ConfigMap history allows easy rollback
5. **Easy Rollback**: `kubectl rollout undo` for instant rollback
6. **Auto-scaling**: HPA scales based on CPU/memory/custom metrics
7. **Self-Healing**: Kubernetes automatically restarts unhealthy pods
8. **Zero-Downtime**: Controlled by Deployment strategy (maxUnavailable: 0)
9. **Resource Management**: CPU and memory limits prevent resource exhaustion
10. **Service Discovery**: Automatic DNS-based service discovery

## Deployment Workflow

### Initial Deployment

```bash
# 1. Create namespace
kubectl create namespace webhook-system

# 2. Create secrets
kubectl create secret generic webhook-secrets \
  --from-literal=CONFIG_RELOAD_ADMIN_TOKEN=your-token \
  -n webhook-system

# 3. Create ConfigMap
kubectl create configmap webhook-config \
  --from-file=webhooks.json \
  --from-file=connections.json \
  -n webhook-system

# 4. Apply deployment
kubectl apply -f k8s/deployment.yaml

# 5. Apply service
kubectl apply -f k8s/service.yaml

# 6. Verify deployment
kubectl get pods -n webhook-system
kubectl get svc -n webhook-system
```

### Updating Configuration

```bash
# Method 1: Update ConfigMap and trigger rolling update
kubectl create configmap webhook-config \
  --from-file=webhooks.json=./webhooks.json \
  --from-file=connections.json=./connections.json \
  -n webhook-system \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl patch deployment webhook-deployment \
  -n webhook-system \
  -p '{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"'$(date +%s)'"}}}}}'

# Method 2: Use Python script
python k8s/rolling_update.py \
  --webhooks-file webhooks.json \
  --connections-file connections.json \
  --wait

# Monitor update
kubectl rollout status deployment/webhook-deployment -n webhook-system
```

### Monitoring and Troubleshooting

```bash
# Check pod status
kubectl get pods -n webhook-system

# View pod logs
kubectl logs -f deployment/webhook-deployment -n webhook-system

# Check deployment status
kubectl describe deployment webhook-deployment -n webhook-system

# Check service endpoints
kubectl get endpoints webhook-service -n webhook-system

# View rollout history
kubectl rollout history deployment/webhook-deployment -n webhook-system

# Check HPA status
kubectl get hpa webhook-hpa -n webhook-system

# Check PDB status
kubectl get pdb webhook-pdb -n webhook-system
```

## Best Practices

1. **Use ConfigMaps for non-sensitive data**: Store configuration in ConfigMaps
2. **Use Secrets for sensitive data**: Store tokens, passwords in Secrets
3. **Set appropriate resource limits**: Prevent resource exhaustion
4. **Use readiness probes**: Ensure pods are ready before receiving traffic
5. **Use liveness probes**: Automatically restart unhealthy pods
6. **Set maxUnavailable: 0**: Ensure zero downtime during updates
7. **Use PodDisruptionBudgets**: Control availability during updates
8. **Monitor rollout status**: Always verify updates complete successfully
9. **Keep rollout history**: Enable history limits for easy rollback
10. **Test in staging first**: Always test configuration changes in staging

## Troubleshooting

### Issue: Pods not starting

**Check**:
```bash
kubectl describe pod <pod-name> -n webhook-system
kubectl logs <pod-name> -n webhook-system
```

### Issue: Rolling update stuck

**Check**:
```bash
kubectl get deployment webhook-deployment -n webhook-system
kubectl describe deployment webhook-deployment -n webhook-system
```

### Issue: ConfigMap not updating

**Check**:
```bash
kubectl get configmap webhook-config -n webhook-system -o yaml
kubectl describe configmap webhook-config -n webhook-system
```

### Issue: Service not routing traffic

**Check**:
```bash
kubectl get svc webhook-service -n webhook-system
kubectl get endpoints webhook-service -n webhook-system
```

## Conclusion

Kubernetes provides native features that make rolling configuration updates much simpler than Docker Compose. The built-in rolling update strategy, health probes, and service load balancing eliminate the need for custom scripts while providing better reliability and observability.

The recommended approach is to use ConfigMaps for configuration storage and leverage Kubernetes' native rolling update mechanism, which provides zero-downtime updates automatically.

