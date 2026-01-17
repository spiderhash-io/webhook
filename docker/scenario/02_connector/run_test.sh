#!/bin/bash
# Run the complete Webhook Connect test scenario
#
# This script demonstrates:
# 1. Basic flow: webhooks received at cloud, forwarded to local via connector
# 2. Resilience: webhooks queued when local is down, delivered when it starts
#
# Usage: ./run_test.sh [test_type]
#   test_type: "basic" (default) or "resilience"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TEST_TYPE="${1:-basic}"
WEBHOOK_COUNT=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_step() {
    echo -e "${GREEN}==>${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

log_error() {
    echo -e "${RED}ERROR:${NC} $1"
}

cleanup() {
    log_step "Cleaning up..."
    docker compose down -v 2>/dev/null || true
    rm -rf logs/local/* logs/cloud/* 2>/dev/null || true
}

wait_for_healthy() {
    local service=$1
    local max_wait=${2:-60}
    local waited=0

    echo "  Waiting for $service to be healthy..."
    while [ $waited -lt $max_wait ]; do
        if docker compose ps $service 2>/dev/null | grep -q "healthy"; then
            echo "  $service is healthy"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    log_error "$service did not become healthy after ${max_wait}s"
    return 1
}

# Trap to cleanup on exit
trap cleanup EXIT

echo ""
echo "=========================================="
echo "Webhook Connect Test Scenario"
echo "Test Type: $TEST_TYPE"
echo "=========================================="
echo ""

# Clean up any previous state
cleanup

# Create log directories
mkdir -p logs/local logs/cloud

if [ "$TEST_TYPE" == "basic" ]; then
    #
    # BASIC TEST: Full flow with all services running
    #
    log_step "Starting basic test..."
    echo ""

    log_step "Step 1: Starting Redis and Cloud Receiver..."
    docker compose up -d redis cloud-receiver
    wait_for_healthy cloud-receiver

    log_step "Step 2: Starting Local Processor..."
    docker compose --profile with-local up -d
    sleep 2  # Wait for local processor

    log_step "Step 3: Registering channel (sending 1 webhook)..."
    chmod +x send_webhooks.sh
    ./send_webhooks.sh 1 100
    sleep 1

    log_step "Step 4: Starting Connector..."
    docker compose --profile with-connector up -d
    sleep 5  # Wait for connector to connect

    log_step "Step 5: Sending $((WEBHOOK_COUNT - 1)) more webhooks to cloud..."
    ./send_webhooks.sh $((WEBHOOK_COUNT - 1)) 100

    log_step "Step 6: Verifying delivery..."
    sleep 3  # Allow time for delivery
    chmod +x verify_results.sh
    ./verify_results.sh $WEBHOOK_COUNT

elif [ "$TEST_TYPE" == "resilience" ]; then
    #
    # RESILIENCE TEST: Queue webhooks while local is down
    #
    log_step "Starting resilience test..."
    echo ""

    log_step "Step 1: Starting Redis and Cloud Receiver ONLY..."
    docker compose up -d redis cloud-receiver
    wait_for_healthy cloud-receiver

    log_step "Step 2: Sending $WEBHOOK_COUNT webhooks to cloud (local is DOWN)..."
    chmod +x send_webhooks.sh
    ./send_webhooks.sh $WEBHOOK_COUNT 100

    log_step "Step 3: Checking queue status..."
    echo "  Webhooks should be queued in Redis..."
    sleep 2

    # Check channel stats via admin API
    echo "  Channel stats:"
    curl -s "http://localhost:8010/admin/webhook-connect/channels/test-channel" \
        -H "Authorization: Bearer admin_secret_123" | python3 -m json.tool 2>/dev/null || echo "  (Channel may not exist yet - first webhook creates it)"

    log_step "Step 4: Starting Local Processor and Connector..."
    docker compose --profile with-local --profile with-connector up -d
    sleep 5  # Wait for connector to connect and start pulling

    log_step "Step 5: Verifying all queued webhooks are delivered..."
    chmod +x verify_results.sh
    ./verify_results.sh $WEBHOOK_COUNT

else
    log_error "Unknown test type: $TEST_TYPE"
    echo "Usage: $0 [basic|resilience]"
    exit 1
fi

echo ""
log_step "Test completed successfully!"
echo ""
