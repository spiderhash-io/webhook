#!/bin/bash

# Performance test runner script
# This script builds the Docker setup and runs performance tests

set -e

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Go to the project root (assuming script is in src/tests/)
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "Webhook Performance Test Setup"
echo "=========================================="
echo

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Build and start services
echo "Building Docker images..."
docker-compose build

echo
echo "Starting services (this may take a minute)..."
docker-compose up -d

echo
echo "Waiting for services to be ready..."
sleep 10

# Wait for ClickHouse to be ready
echo "Waiting for ClickHouse to be ready..."
for i in {1..30}; do
    if docker-compose exec -T clickhouse wget --spider -q http://localhost:8123/ping 2>/dev/null; then
        echo "ClickHouse is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: ClickHouse did not become ready in time"
        docker-compose logs clickhouse
        exit 1
    fi
    sleep 2
done

# Wait for webhook instances to be ready
echo "Waiting for webhook instances to be ready..."
sleep 5

# Check if webhook instances are responding
for port in 8000 8001 8002 8003 8004; do
    echo -n "Checking instance on port $port... "
    if curl -s -f http://localhost:$port/ > /dev/null 2>&1; then
        echo "OK"
    else
        echo "NOT READY (this is OK, may need more time)"
    fi
done

echo
echo "=========================================="
echo "Running Performance Test"
echo "=========================================="
echo

# Run the performance test
python3 src/tests/performance_test_multi_instance.py

echo
echo "=========================================="
echo "Test Complete"
echo "=========================================="
echo
echo "To view logs:"
echo "  docker-compose logs -f webhook-1"
echo
echo "To check ClickHouse data:"
echo "  docker-compose exec clickhouse clickhouse-client --query 'SELECT count() FROM webhook_logs'"
echo
echo "To stop services:"
echo "  docker-compose down"
echo

