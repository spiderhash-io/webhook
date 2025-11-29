#!/bin/bash
# Script to run integration tests with proper setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Integration Test Runner"
echo "======================"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    exit 1
fi

# Determine docker compose command
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
elif docker-compose version &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "ERROR: docker compose or docker-compose not found"
    exit 1
fi

# Check if sudo is needed
if docker ps &> /dev/null; then
    DOCKER_CMD="$DOCKER_COMPOSE"
else
    echo "Note: Using sudo for Docker commands"
    DOCKER_CMD="sudo $DOCKER_COMPOSE"
fi

cd "$SCRIPT_DIR"

echo "Starting integration test services..."
$DOCKER_CMD up -d redis rabbitmq clickhouse redpanda api-server

echo ""
echo "Waiting for services to be healthy..."
sleep 10

echo ""
echo "Checking service health..."
$DOCKER_CMD ps

echo ""
echo "Running integration tests..."
cd "$PROJECT_ROOT"
pytest tests/integration/ -v -m integration "$@"

echo ""
echo "Tests completed. Services are still running."
echo "To stop services, run: cd tests/integration/config && $DOCKER_CMD down"

