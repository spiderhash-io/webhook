#!/bin/bash
# Orchestration script to run the live reload test scenario
# This script starts the services and runs the test scripts

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill ${WEBHOOK_PID} ${CONFIG_PID} 2>/dev/null || true
    wait ${WEBHOOK_PID} ${CONFIG_PID} 2>/dev/null || true
    exit 0
}

# Trap Ctrl+C
trap cleanup INT TERM

echo "=========================================="
echo "Live Config Reload Test Scenario"
echo "=========================================="
echo ""

# Create logs directory if it doesn't exist
mkdir -p logs

# Start docker compose
echo "Starting webhook service..."
docker-compose up -d

echo ""
echo "Waiting for webhook service to be ready..."
sleep 5

# Wait for service to be healthy
for i in {1..30}; do
    if curl -s -f "http://localhost:8000/" > /dev/null 2>&1; then
        echo "Webhook service is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: Webhook service did not become ready"
        docker-compose logs webhook
        exit 1
    fi
    sleep 1
done

echo ""
echo "=========================================="
echo "Starting test scripts..."
echo "=========================================="
echo ""

# Wait for specified duration (default 60 seconds)
DURATION=${1:-60}
echo "This will run for ${DURATION} seconds, then stop automatically."
echo "You can also press Ctrl+C to stop early."
echo ""

# Run webhook sender in background
echo "Starting webhook sender..."
./send_webhooks.sh > /tmp/webhook_sender.log 2>&1 &
WEBHOOK_PID=$!

# Run config changer in background
echo "Starting config changer..."
./change_config.sh > /tmp/config_changer.log 2>&1 &
CONFIG_PID=$!

echo "Running test for ${DURATION} seconds..."
echo "Webhook sender PID: ${WEBHOOK_PID}"
echo "Config changer PID: ${CONFIG_PID}"
echo ""

# Wait for specified duration
sleep ${DURATION}

# Stop the scripts
echo ""
echo "Stopping test scripts..."
kill ${WEBHOOK_PID} ${CONFIG_PID} 2>/dev/null || true
wait ${WEBHOOK_PID} ${CONFIG_PID} 2>/dev/null || true

echo ""
echo "=========================================="
echo "Test completed!"
echo "=========================================="
echo ""
echo "Verifying results..."
./verify_results.sh

echo ""
echo "To view webhook sender logs: cat /tmp/webhook_sender.log"
echo "To view config changer logs: cat /tmp/config_changer.log"
echo ""
echo "To stop services: docker-compose down"
echo "To clean logs: rm -rf logs/*"
