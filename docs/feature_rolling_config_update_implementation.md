# Rolling Config Update Implementation Guide

## Overview

This document describes the implementation steps for enabling rolling configuration updates across multiple webhook instances with zero downtime. The approach uses a load balancer (Nginx) to route traffic and a rolling update script to update instances one at a time.

## Architecture

```
External Traffic → Nginx Load Balancer (Port 80)
                      ↓
        ┌─────────────┼─────────────┐
        ↓             ↓             ↓
   Webhook-1      Webhook-2      Webhook-N
   (Drained)      (Active)       (Active)
        ↓
   Config Update
        ↓
   Health Check
        ↓
   Re-enable
```

## Implementation Steps

### Step 1: Add Health Endpoint

Add a health check endpoint to each webhook instance for load balancer health checks.

**Location**: `src/main.py`

**Implementation**:

```python
@app.get("/admin/health")
async def health_check():
    """
    Health check endpoint for load balancers and monitoring.
    
    Returns 200 if the instance is healthy and ready to accept traffic.
    Returns 503 if the instance is unhealthy or draining.
    
    Returns:
    {
        "status": "healthy" | "unhealthy" | "draining",
        "config_manager": true/false,
        "timestamp": "2024-01-15T10:30:00Z",
        "instance_id": "webhook-1"
    }
    """
    global config_manager
    import socket
    
    instance_id = os.getenv("INSTANCE_ID", socket.gethostname())
    
    # Check if instance is draining
    global draining
    if draining:
        return JSONResponse(
            status_code=503,
            content={
                "status": "draining",
                "config_manager": config_manager is not None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "instance_id": instance_id,
                "message": "Instance is draining traffic"
            }
        )
    
    # Basic health checks
    checks = {
        "status": "healthy",
        "config_manager": config_manager is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "instance_id": instance_id
    }
    
    # Optional: Check critical dependencies
    # Uncomment and implement if needed
    # try:
    #     checks["redis"] = await check_redis_health()
    #     checks["rabbitmq"] = await check_rabbitmq_health()
    # except Exception as e:
    #     checks["status"] = "unhealthy"
    #     checks["error"] = str(e)
    
    # Determine overall health
    is_healthy = checks["config_manager"]  # Add more checks as needed
    
    if is_healthy:
        return JSONResponse(content=checks, status_code=200)
    else:
        return JSONResponse(
            status_code=503,
            content={**checks, "status": "unhealthy"}
        )
```

**Add global draining flag** (at the top of `src/main.py` with other globals):

```python
draining = False  # Global flag to indicate instance is draining
```

### Step 2: Add Drain/Undrain Endpoints

Add endpoints to gracefully drain traffic from an instance before updates.

**Location**: `src/main.py`

**Implementation**:

```python
@app.post("/admin/drain")
async def drain_traffic(request: Request):
    """
    Mark instance as draining (stop accepting new requests).
    
    This endpoint sets the instance to draining mode, which causes:
    - Health checks to return 503
    - Load balancer to stop routing new traffic
    - In-flight requests to complete normally
    
    Authentication required via CONFIG_RELOAD_ADMIN_TOKEN.
    
    Returns:
    {
        "status": "draining",
        "instance_id": "webhook-1",
        "timestamp": "2024-01-15T10:30:00Z"
    }
    """
    global draining
    
    # Authentication
    admin_token = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN", "").strip()
    if admin_token:
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header.strip()
        
        import hmac
        if not hmac.compare_digest(token.encode('utf-8'), admin_token.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    draining = True
    instance_id = os.getenv("INSTANCE_ID", socket.gethostname())
    
    return JSONResponse(content={
        "status": "draining",
        "instance_id": instance_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "Instance is now draining. Health checks will return 503."
    })


@app.post("/admin/undrain")
async def undrain_traffic(request: Request):
    """
    Stop draining (resume accepting requests).
    
    This endpoint removes the draining flag, allowing the instance
    to accept new traffic again.
    
    Authentication required via CONFIG_RELOAD_ADMIN_TOKEN.
    
    Returns:
    {
        "status": "active",
        "instance_id": "webhook-1",
        "timestamp": "2024-01-15T10:30:00Z"
    }
    """
    global draining
    
    # Authentication
    admin_token = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN", "").strip()
    if admin_token:
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header.strip()
        
        import hmac
        if not hmac.compare_digest(token.encode('utf-8'), admin_token.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    draining = False
    instance_id = os.getenv("INSTANCE_ID", socket.gethostname())
    
    return JSONResponse(content={
        "status": "active",
        "instance_id": instance_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "Instance is now active and accepting traffic."
    })


@app.get("/admin/drain-status")
async def drain_status():
    """
    Get current drain status of the instance.
    
    Returns:
    {
        "draining": true/false,
        "instance_id": "webhook-1",
        "timestamp": "2024-01-15T10:30:00Z"
    }
    """
    global draining
    instance_id = os.getenv("INSTANCE_ID", socket.gethostname())
    
    return JSONResponse(content={
        "draining": draining,
        "instance_id": instance_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
```

**Update webhook endpoint to respect draining flag** (in `src/main.py`, modify the webhook handler):

```python
@app.post("/webhook/{webhook_id}")
async def read_webhook(webhook_id: str, request: Request):
    """Process webhook request."""
    global draining
    
    # Check if instance is draining
    if draining:
        return JSONResponse(
            status_code=503,
            content={
                "error": "Service temporarily unavailable",
                "message": "Instance is draining traffic for maintenance"
            }
        )
    
    # ... rest of existing webhook processing logic ...
```

### Step 3: Set Up Nginx Load Balancer

Create Nginx configuration files for load balancing.

**Create directory structure**:

```bash
mkdir -p nginx
```

**nginx/nginx.conf**:

```nginx
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/conf.d/upstream.conf;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Upstream configuration (loaded from conf.d/upstream.conf)
    upstream webhook_backend {
        least_conn;  # Load balancing method: least connections
        include /etc/nginx/conf.d/backend_servers.conf;
    }

    server {
        listen 80;
        server_name _;
        
        # Main webhook endpoint
        location / {
            proxy_pass http://webhook_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 5s;
            proxy_send_timeout 10s;
            proxy_read_timeout 10s;
            
            # Health check
            proxy_next_upstream error timeout http_502 http_503 http_504;
            proxy_next_upstream_tries 3;
            proxy_next_upstream_timeout 10s;
        }
        
        # Admin endpoints (for config updates, health checks, etc.)
        location /admin/ {
            proxy_pass http://webhook_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            
            # Longer timeout for admin operations
            proxy_connect_timeout 10s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }
        
        # Health check endpoint for Nginx itself
        location /nginx-health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
```

**nginx/conf.d/backend_servers.conf**:

```nginx
# Backend server definitions
# This file is managed by the rolling update script
# DO NOT EDIT MANUALLY

server webhook-1:8000 max_fails=3 fail_timeout=30s;
server webhook-2:8000 max_fails=3 fail_timeout=30s;
server webhook-3:8000 max_fails=3 fail_timeout=30s;
server webhook-4:8000 max_fails=3 fail_timeout=30s;
server webhook-5:8000 max_fails=3 fail_timeout=30s;
```

**Update docker-compose.yaml** to add Nginx service:

```yaml
services:
  # Nginx Load Balancer
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
    depends_on:
      - webhook-1
      - webhook-2
      - webhook-3
      - webhook-4
      - webhook-5
    networks:
      - webhook-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost/nginx-health"]
      interval: 5s
      timeout: 3s
      retries: 3

  # Update webhook services to remove external port mappings
  # and add health checks
  webhook-1:
    build: .
    expose:
      - "8000"  # Only expose internally, not to host
    volumes:
      - ./src:/app/src
      - ./connections.docker.json:/app/connections.json
      - ./webhooks.performance.json:/app/webhooks.json
    environment:
      - REDIS_HOST=redis
      - RABBITMQ_HOST=rabbitmq
      - CLICKHOUSE_HOST=clickhouse
      - INSTANCE_ID=webhook-1
      - CONFIG_RELOAD_ADMIN_TOKEN=${CONFIG_RELOAD_ADMIN_TOKEN:-changeme}
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/admin/health')"]
      interval: 5s
      timeout: 3s
      retries: 3
      start_period: 10s
    depends_on:
      redis:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
      clickhouse:
        condition: service_healthy
    networks:
      - webhook-network
    restart: unless-stopped

  # Repeat for webhook-2 through webhook-5 with appropriate INSTANCE_ID
```

### Step 4: Create Rolling Update Script

Create a script to perform rolling updates.

**rolling-update.sh**:

```bash
#!/bin/bash
# Rolling Config Update Script
#
# This script performs zero-downtime configuration updates by:
# 1. Draining traffic from one instance
# 2. Updating the configuration
# 3. Verifying health
# 4. Re-enabling the instance
# 5. Repeating for the next instance
#
# Usage:
#   ./rolling-update.sh [config_type] [config_file]
#   ./rolling-update.sh webhooks webhooks.json
#   ./rolling-update.sh connections connections.json

set -euo pipefail

# Configuration
CONFIG_TYPE="${1:-webhooks}"  # webhooks or connections
CONFIG_FILE="${2:-webhooks.json}"
INSTANCES=("webhook-1" "webhook-2" "webhook-3" "webhook-4" "webhook-5")
NGINX_CONF="./nginx/conf.d/backend_servers.conf"
DRAIN_WAIT_TIME=15  # Seconds to wait for connections to drain
HEALTH_CHECK_RETRIES=5
HEALTH_CHECK_INTERVAL=2

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Config file '$CONFIG_FILE' not found${NC}"
    exit 1
fi

# Get admin token from environment
ADMIN_TOKEN="${CONFIG_RELOAD_ADMIN_TOKEN:-changeme}"
if [ "$ADMIN_TOKEN" = "changeme" ]; then
    echo -e "${YELLOW}Warning: Using default admin token. Set CONFIG_RELOAD_ADMIN_TOKEN for production.${NC}"
fi

# Function to print colored messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to drain instance (set draining flag)
drain_instance() {
    local instance=$1
    log_info "Draining $instance..."
    
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "http://${instance}:8000/admin/drain" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" 2>/dev/null || echo -e "\n000")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" -eq 200 ]; then
        log_info "✓ $instance is now draining"
        return 0
    else
        log_error "Failed to drain $instance (HTTP $http_code)"
        return 1
    fi
}

# Function to remove instance from Nginx upstream
remove_from_nginx() {
    local instance=$1
    log_info "Removing $instance from Nginx load balancer..."
    
    # Comment out the server line
    sed -i.bak "s/^server ${instance}:8000/# server ${instance}:8000 # DRAINED/" "$NGINX_CONF"
    
    # Reload Nginx
    if docker compose exec -T nginx nginx -s reload >/dev/null 2>&1; then
        log_info "✓ Nginx reloaded"
        log_info "Waiting ${DRAIN_WAIT_TIME}s for connections to drain..."
        sleep "$DRAIN_WAIT_TIME"
        return 0
    else
        log_error "Failed to reload Nginx"
        return 1
    fi
}

# Function to update config on instance
update_instance_config() {
    local instance=$1
    log_info "Updating $CONFIG_TYPE config on $instance..."
    
    # Read and validate JSON
    if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
        log_error "Invalid JSON in $CONFIG_FILE"
        return 1
    fi
    
    # Prepare config data
    CONFIG_DATA=$(jq -c . "$CONFIG_FILE")
    
    # Send config update
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "http://${instance}:8000/admin/config-update" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"type\": \"${CONFIG_TYPE}\", \"config\": ${CONFIG_DATA}}" \
        --max-time 30 2>/dev/null || echo -e "\n000")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [ "$http_code" -eq 200 ]; then
        log_info "✓ $instance config updated successfully"
        return 0
    else
        log_error "✗ $instance update failed: HTTP $http_code"
        echo "$body" | jq . 2>/dev/null || echo "$body"
        return 1
    fi
}

# Function to verify instance health
verify_instance_health() {
    local instance=$1
    local retries=$HEALTH_CHECK_RETRIES
    local interval=$HEALTH_CHECK_INTERVAL
    
    log_info "Verifying $instance health..."
    
    while [ $retries -gt 0 ]; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            "http://${instance}:8000/admin/health" \
            --max-time 5 2>/dev/null || echo "000")
        
        if [ "$http_code" -eq 200 ]; then
            log_info "✓ $instance is healthy"
            return 0
        fi
        
        retries=$((retries - 1))
        if [ $retries -gt 0 ]; then
            log_warn "Health check failed (HTTP $http_code), retrying in ${interval}s... ($retries retries left)"
            sleep "$interval"
        fi
    done
    
    log_error "✗ $instance health check failed after all retries"
    return 1
}

# Function to undrain instance
undrain_instance() {
    local instance=$1
    log_info "Undraining $instance..."
    
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "http://${instance}:8000/admin/undrain" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" 2>/dev/null || echo -e "\n000")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" -eq 200 ]; then
        log_info "✓ $instance is now active"
        return 0
    else
        log_error "Failed to undrain $instance (HTTP $http_code)"
        return 1
    fi
}

# Function to add instance back to Nginx upstream
add_to_nginx() {
    local instance=$1
    log_info "Adding $instance back to Nginx load balancer..."
    
    # Uncomment the server line
    sed -i.bak "s/^# server ${instance}:8000 # DRAINED/server ${instance}:8000/" "$NGINX_CONF"
    
    # Reload Nginx
    if docker compose exec -T nginx nginx -s reload >/dev/null 2>&1; then
        log_info "✓ $instance added back to load balancer"
        return 0
    else
        log_error "Failed to reload Nginx"
        return 1
    fi
}

# Function to rollback Nginx config on error
rollback_nginx() {
    log_warn "Rolling back Nginx configuration..."
    if [ -f "${NGINX_CONF}.bak" ]; then
        mv "${NGINX_CONF}.bak" "$NGINX_CONF"
        docker compose exec -T nginx nginx -s reload >/dev/null 2>&1
    fi
}

# Main rolling update loop
main() {
    log_info "========================================="
    log_info "Starting Rolling Config Update"
    log_info "========================================="
    log_info "Config type: $CONFIG_TYPE"
    log_info "Config file: $CONFIG_FILE"
    log_info "Instances: ${INSTANCES[*]}"
    log_info ""
    
    # Verify Nginx is running
    if ! docker compose ps nginx | grep -q "Up"; then
        log_error "Nginx is not running. Please start it first: docker compose up -d nginx"
        exit 1
    fi
    
    # Backup Nginx config
    cp "$NGINX_CONF" "${NGINX_CONF}.backup"
    
    # Process each instance
    for instance in "${INSTANCES[@]}"; do
        log_info "========================================="
        log_info "Processing $instance"
        log_info "========================================="
        
        # Step 1: Drain instance (set draining flag)
        if ! drain_instance "$instance"; then
            log_error "Failed to drain $instance. Aborting."
            rollback_nginx
            exit 1
        fi
        
        # Step 2: Remove from Nginx upstream
        if ! remove_from_nginx "$instance"; then
            log_error "Failed to remove $instance from Nginx. Aborting."
            rollback_nginx
            exit 1
        fi
        
        # Step 3: Update config
        if ! update_instance_config "$instance"; then
            log_error "Failed to update $instance. NOT re-enabling."
            log_warn "Manual intervention required for $instance"
            continue
        fi
        
        # Step 4: Verify health
        if ! verify_instance_health "$instance"; then
            log_error "Health check failed for $instance. NOT re-enabling."
            log_warn "Manual intervention required for $instance"
            continue
        fi
        
        # Step 5: Undrain instance
        if ! undrain_instance "$instance"; then
            log_warn "Failed to undrain $instance, but continuing..."
        fi
        
        # Step 6: Add back to Nginx
        if ! add_to_nginx "$instance"; then
            log_error "Failed to add $instance back to Nginx"
            rollback_nginx
            exit 1
        fi
        
        log_info "✓ $instance update completed successfully"
        log_info ""
        
        # Brief pause between instances
        if [ "$instance" != "${INSTANCES[-1]}" ]; then
            sleep 3
        fi
    done
    
    # Cleanup backup
    rm -f "${NGINX_CONF}.backup" "${NGINX_CONF}.bak"
    
    log_info "========================================="
    log_info "Rolling update completed successfully!"
    log_info "========================================="
}

# Run main function
main
```

**Make script executable**:

```bash
chmod +x rolling-update.sh
```

### Step 5: Testing Procedure

#### 5.1 Test with Single Instance First

**Test health endpoint**:

```bash
# Start a single instance
docker compose up -d webhook-1

# Test health endpoint
curl http://localhost:8000/admin/health

# Expected: {"status": "healthy", ...}
```

**Test drain/undrain**:

```bash
# Set admin token
export CONFIG_RELOAD_ADMIN_TOKEN=your-secret-token

# Drain instance
curl -X POST http://localhost:8000/admin/drain \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN"

# Check health (should return 503)
curl http://localhost:8000/admin/health

# Undrain instance
curl -X POST http://localhost:8000/admin/undrain \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN"

# Check health (should return 200)
curl http://localhost:8000/admin/health
```

**Test config update**:

```bash
# Update config
curl -X POST http://localhost:8000/admin/config-update \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type": "webhooks", "config": {...}}'
```

#### 5.2 Test with Multiple Instances

**Start all services**:

```bash
# Start all webhook instances and Nginx
docker compose up -d

# Verify all instances are healthy
for i in {1..5}; do
  echo "Checking webhook-$i..."
  curl -s http://webhook-$i:8000/admin/health | jq .
done
```

**Test load balancing**:

```bash
# Send multiple requests through Nginx
for i in {1..10}; do
  curl -s http://localhost/webhook/test_webhook \
    -H "Authorization: Bearer test-token" \
    -d '{"test": "data"}' | jq .instance_id
done

# Should see requests distributed across instances
```

**Test rolling update**:

```bash
# Make a backup of current config
cp webhooks.json webhooks.json.backup

# Make a test change
jq '.test_webhook.module = "log"' webhooks.json > webhooks.json.new
mv webhooks.json.new webhooks.json

# Run rolling update
export CONFIG_RELOAD_ADMIN_TOKEN=your-secret-token
./rolling-update.sh webhooks webhooks.json

# Verify all instances have new config
for i in {1..5}; do
  echo "Checking webhook-$i config version..."
  curl -s http://webhook-$i:8000/admin/config-version \
    -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN" | jq .
done
```

#### 5.3 Test Failure Scenarios

**Test instance failure during update**:

```bash
# Stop an instance during update
docker compose stop webhook-3

# Run rolling update (should handle failure gracefully)
./rolling-update.sh webhooks webhooks.json

# Restart instance
docker compose start webhook-3
```

**Test invalid config**:

```bash
# Create invalid config
echo '{"invalid": json}' > webhooks.invalid.json

# Try rolling update (should fail on first instance)
./rolling-update.sh webhooks webhooks.invalid.json

# Verify no instances were updated
```

## Verification Checklist

After implementation, verify:

- [ ] Health endpoint returns 200 for healthy instances
- [ ] Health endpoint returns 503 for draining instances
- [ ] Drain endpoint sets draining flag
- [ ] Undrain endpoint clears draining flag
- [ ] Nginx routes traffic to healthy instances
- [ ] Nginx excludes drained instances
- [ ] Rolling update script updates instances sequentially
- [ ] Rolling update script handles failures gracefully
- [ ] All instances remain accessible during update
- [ ] Zero downtime during rolling updates

## Troubleshooting

### Issue: Nginx not reloading

**Solution**: Check Nginx logs:
```bash
docker compose logs nginx
```

### Issue: Instance not draining

**Solution**: Check if drain endpoint is accessible:
```bash
curl -v http://webhook-1:8000/admin/drain \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN"
```

### Issue: Health check failing

**Solution**: Verify health endpoint:
```bash
curl http://webhook-1:8000/admin/health
```

### Issue: Config update failing

**Solution**: Check config file validity:
```bash
jq . webhooks.json
```

## Production Considerations

1. **Set strong admin token**: Use a secure token in production
2. **Monitor during updates**: Watch logs and metrics during rolling updates
3. **Test in staging first**: Always test rolling updates in staging environment
4. **Have rollback plan**: Keep backups of working configurations
5. **Set appropriate timeouts**: Adjust `DRAIN_WAIT_TIME` based on your traffic patterns
6. **Monitor instance health**: Set up alerts for unhealthy instances
7. **Document instance IDs**: Keep track of which instances are which

## Next Steps

1. Implement health endpoint
2. Implement drain/undrain endpoints
3. Set up Nginx load balancer
4. Create rolling update script
5. Test with single instance
6. Test with multiple instances
7. Test failure scenarios
8. Deploy to production

