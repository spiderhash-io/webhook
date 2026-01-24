#!/bin/bash
# Test script: Validate webhook functionality in Kubernetes
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

SCENARIO_DIR="$(get_scenario_dir)"
PROJECT_ROOT="$(get_project_root)"

# Test type (basic, scaling, ingress, all)
TEST_TYPE="${1:-basic}"

echo ""
echo "=========================================="
echo "Kubernetes Test Scenario - Test ($TEST_TYPE)"
echo "=========================================="
echo ""

# Check if cluster exists
if ! cluster_exists; then
    log_error "Kind cluster '$CLUSTER_NAME' does not exist. Run setup.sh first."
    exit 1
fi

# Ensure correct context
kubectl config use-context "kind-${CLUSTER_NAME}" &>/dev/null

# Trap for cleanup
cleanup_test() {
    stop_port_forward
}
trap cleanup_test EXIT

# ==========================================
# Basic Test
# ==========================================
run_basic_test() {
    log_step "Running basic test..."
    echo ""

    # Check pods are running
    log_step "Checking pod status..."
    kubectl get pods -n "$NAMESPACE"

    local pod_status=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=core-webhook-module -o jsonpath='{.items[0].status.phase}' 2>/dev/null)
    if [ "$pod_status" != "Running" ]; then
        log_error "Pod is not running (status: $pod_status)"
        kubectl describe pods -n "$NAMESPACE" -l app.kubernetes.io/name=core-webhook-module
        return 1
    fi
    log_success "Pod is running"

    # Start port forward
    start_port_forward "webhook-service" 8000 80
    sleep 2

    # Test health endpoint
    log_step "Testing /health endpoint..."
    local health_response=$(curl -s -w "\n%{http_code}" "http://localhost:8000/health")
    local health_code=$(echo "$health_response" | tail -1)
    local health_body=$(echo "$health_response" | sed '$d')

    if [ "$health_code" = "200" ]; then
        log_success "Health check passed (HTTP $health_code)"
        log_info "Response: $health_body"
    else
        log_error "Health check failed (HTTP $health_code)"
        return 1
    fi

    # Test root endpoint
    log_step "Testing / endpoint..."
    local root_response=$(curl -s -w "\n%{http_code}" "http://localhost:8000/")
    local root_code=$(echo "$root_response" | tail -1)

    if [ "$root_code" = "200" ]; then
        log_success "Root endpoint check passed (HTTP $root_code)"
    else
        log_error "Root endpoint check failed (HTTP $root_code)"
        return 1
    fi

    # Send test webhooks
    log_step "Sending 10 test webhooks..."
    local success_count=0
    local fail_count=0

    for i in $(seq 1 10); do
        local response=$(curl -s -w "\n%{http_code}" \
            -X POST "http://localhost:8000/webhook/test" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer test_token_123" \
            -d "{\"test_id\": $i, \"message\": \"Test webhook $i\"}")

        local code=$(echo "$response" | tail -1)
        if [ "$code" = "200" ]; then
            ((success_count++))
            echo -n "."
        else
            ((fail_count++))
            echo -n "x"
        fi
    done
    echo ""

    log_info "Success: $success_count, Failed: $fail_count"

    if [ "$fail_count" -gt 0 ]; then
        log_warn "Some webhooks failed"
    fi

    # Check pod logs for received webhooks
    log_step "Checking pod logs for received webhooks..."
    local pod_name=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=core-webhook-module -o jsonpath='{.items[0].metadata.name}')

    echo ""
    log_info "Recent logs:"
    kubectl logs -n "$NAMESPACE" "$pod_name" --tail=20

    echo ""
    if [ "$success_count" -eq 10 ]; then
        log_success "Basic test PASSED"
        return 0
    else
        log_warn "Basic test completed with some failures"
        return 1
    fi
}

# ==========================================
# Scaling Test
# ==========================================
run_scaling_test() {
    log_step "Running scaling test..."
    echo ""

    # Check if metrics-server is installed
    if ! kubectl get deployment metrics-server -n kube-system &>/dev/null; then
        log_warn "Metrics-server not installed. Installing..."
        kubectl apply -f "${SCENARIO_DIR}/addons/metrics-server.yaml"
        wait_for_deployment "metrics-server" "kube-system" 120
    fi

    # Check if HPA exists
    if ! kubectl get hpa webhook-hpa -n "$NAMESPACE" &>/dev/null; then
        log_warn "HPA not configured. Applying..."
        kubectl apply -f "${PROJECT_ROOT}/kubernetes/base/hpa.yaml"
    fi

    # Wait for metrics to be available
    log_step "Waiting for metrics to be available..."
    local attempts=0
    while [ $attempts -lt 30 ]; do
        if kubectl top pods -n "$NAMESPACE" &>/dev/null; then
            log_success "Metrics available"
            break
        fi
        ((attempts++))
        echo -n "."
        sleep 5
    done
    echo ""

    if [ $attempts -eq 30 ]; then
        log_warn "Metrics not available yet. HPA may not function correctly."
    fi

    # Show current HPA status
    log_step "Current HPA status:"
    kubectl get hpa -n "$NAMESPACE"

    # Show pod metrics
    log_step "Current pod metrics:"
    kubectl top pods -n "$NAMESPACE" 2>/dev/null || log_warn "Metrics not yet available"

    # Start port forward
    start_port_forward "webhook-service" 8000 80
    sleep 2

    # Generate load
    log_step "Generating load (100 requests)..."
    local start_time=$(date +%s)

    for i in $(seq 1 100); do
        curl -s -o /dev/null \
            -X POST "http://localhost:8000/webhook/test" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer test_token_123" \
            -d "{\"test_id\": $i, \"load_test\": true}" &

        # Rate limit to ~10 req/s
        if [ $((i % 10)) -eq 0 ]; then
            wait
            echo -n "."
        fi
    done
    wait
    echo ""

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_info "Sent 100 requests in ${duration}s"

    # Show HPA status after load
    sleep 5
    log_step "HPA status after load:"
    kubectl get hpa -n "$NAMESPACE"

    log_step "Pod count:"
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=core-webhook-module

    echo ""
    log_success "Scaling test completed"
    log_info "Note: HPA scaling may take a few minutes to trigger based on metrics"
}

# ==========================================
# Ingress Test
# ==========================================
run_ingress_test() {
    log_step "Running ingress test..."
    echo ""

    # Check if ingress controller is installed
    if ! kubectl get deployment ingress-nginx-controller -n ingress-nginx &>/dev/null; then
        log_warn "Nginx ingress controller not installed. Installing..."
        "${SCENARIO_DIR}/addons/install-ingress-nginx.sh"
    fi

    # Check if ingress resource exists
    if ! kubectl get ingress webhook-ingress -n "$NAMESPACE" &>/dev/null; then
        log_warn "Ingress resource not configured. Applying..."
        kubectl apply -f "${PROJECT_ROOT}/kubernetes/optional/ingress-nginx.yaml"
    fi

    # Wait for ingress controller
    log_step "Waiting for ingress controller..."
    wait_for_pods "app.kubernetes.io/component=controller" "ingress-nginx" 120

    # Show ingress status
    log_step "Ingress status:"
    kubectl get ingress -n "$NAMESPACE"

    # Test via ingress (port 18080 is mapped to ingress in kind-cluster.yaml)
    log_step "Testing via ingress (localhost:18080)..."
    sleep 5  # Give ingress time to configure

    # Test health endpoint via ingress
    local health_response=$(curl -s -w "\n%{http_code}" \
        -H "Host: webhook.example.com" \
        "http://localhost:18080/health")
    local health_code=$(echo "$health_response" | tail -1)

    if [ "$health_code" = "200" ]; then
        log_success "Ingress health check passed (HTTP $health_code)"
    else
        log_warn "Ingress health check returned HTTP $health_code"
        log_info "This may be expected if ingress is still configuring"

        # Try direct service access for comparison
        log_step "Trying direct service access for comparison..."
        start_port_forward "webhook-service" 8001 80
        sleep 2

        local direct_response=$(curl -s -w "\n%{http_code}" "http://localhost:8001/health")
        local direct_code=$(echo "$direct_response" | tail -1)
        log_info "Direct service access: HTTP $direct_code"
    fi

    # Test webhook via ingress
    log_step "Testing webhook via ingress..."
    local webhook_response=$(curl -s -w "\n%{http_code}" \
        -X POST "http://localhost:18080/webhook/test" \
        -H "Host: webhook.example.com" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer test_token_123" \
        -d '{"test": "ingress"}')
    local webhook_code=$(echo "$webhook_response" | tail -1)

    if [ "$webhook_code" = "200" ]; then
        log_success "Ingress webhook test passed (HTTP $webhook_code)"
    else
        log_warn "Ingress webhook test returned HTTP $webhook_code"
    fi

    echo ""
    log_success "Ingress test completed"
}

# ==========================================
# Run Tests
# ==========================================
case "$TEST_TYPE" in
    basic)
        run_basic_test
        ;;
    scaling)
        run_scaling_test
        ;;
    ingress)
        run_ingress_test
        ;;
    all)
        run_basic_test
        echo ""
        run_scaling_test
        echo ""
        run_ingress_test
        ;;
    *)
        log_error "Unknown test type: $TEST_TYPE"
        echo "Usage: $0 [basic|scaling|ingress|all]"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
log_success "Test run complete!"
echo "=========================================="
