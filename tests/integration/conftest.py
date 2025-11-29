"""
Pytest configuration and fixtures for integration tests.

This module provides fixtures for:
- Docker services management
- FastAPI test client using httpx (real HTTP calls)
- Service health checks
- Test data cleanup
"""

import pytest
import httpx
import asyncio
from typing import AsyncGenerator
from tests.integration.utils import (
    check_redis_health,
    check_rabbitmq_health,
    check_clickhouse_health,
    check_kafka_health,
    check_api_health,
    check_docker_services,
    wait_for_service,
    cleanup_redis_keys,
)
from tests.integration.test_config import (
    API_BASE_URL,
    TEST_REDIS_PREFIX,
)


@pytest.fixture(scope="session")
def docker_services_available() -> bool:
    """Check if Docker services are available before running tests."""
    services = check_docker_services()
    all_available = all(services.values())
    
    if not all_available:
        pytest.skip(
            f"Docker services not available. Status: {services}. "
            "Start services with: docker compose up -d redis rabbitmq clickhouse redpanda"
        )
    
    return all_available


@pytest.fixture(scope="session")
async def services_ready(docker_services_available) -> bool:
    """Wait for all services to be ready."""
    if not docker_services_available:
        pytest.skip("Docker services not available")
    
    # Wait for services to be healthy
    redis_ready = await wait_for_service(
        check_redis_health,
        timeout=30.0,
        service_name="Redis"
    )
    rabbitmq_ready = await wait_for_service(
        check_rabbitmq_health,
        timeout=30.0,
        service_name="RabbitMQ"
    )
    clickhouse_ready = await wait_for_service(
        check_clickhouse_health,
        timeout=30.0,
        service_name="ClickHouse"
    )
    kafka_ready = await wait_for_service(
        check_kafka_health,
        timeout=30.0,
        service_name="Kafka/Redpanda"
    )
    
    if not (redis_ready and rabbitmq_ready and clickhouse_ready and kafka_ready):
        pytest.skip(
            f"Services not ready. Redis: {redis_ready}, "
            f"RabbitMQ: {rabbitmq_ready}, ClickHouse: {clickhouse_ready}, "
            f"Kafka: {kafka_ready}"
        )
    
    return True


@pytest.fixture(scope="session")
async def api_server_ready(services_ready) -> bool:
    """Check if FastAPI server is running."""
    if not services_ready:
        pytest.skip("Services not ready")
    
    api_ready = await wait_for_service(
        check_api_health,
        timeout=10.0,
        service_name="FastAPI Server"
    )
    
    if not api_ready:
        pytest.skip(
            f"FastAPI server not available at {API_BASE_URL}. "
            "Start server with: uvicorn src.main:app --port 8000"
        )
    
    return True


@pytest.fixture
async def http_client(api_server_ready) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an httpx AsyncClient for making real HTTP requests."""
    if not api_server_ready:
        pytest.skip("API server not ready")
    
    async with httpx.AsyncClient(base_url=API_BASE_URL, timeout=30.0) as client:
        yield client


@pytest.fixture
async def authenticated_client(
    http_client: httpx.AsyncClient
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an authenticated httpx client."""
    from tests.integration.test_config import TEST_AUTH_TOKEN
    
    http_client.headers.update({
        "Authorization": f"Bearer {TEST_AUTH_TOKEN}"
    })
    yield http_client
    http_client.headers.pop("Authorization", None)


@pytest.fixture(autouse=True)
async def cleanup_test_data():
    """Clean up test data before and after each test."""
    # Cleanup before test
    await cleanup_redis_keys(TEST_REDIS_PREFIX)
    
    yield
    
    # Cleanup after test
    await cleanup_redis_keys(TEST_REDIS_PREFIX)


@pytest.fixture
def test_webhook_id() -> str:
    """Get test webhook ID."""
    from tests.integration.test_config import TEST_WEBHOOK_ID
    return TEST_WEBHOOK_ID


@pytest.fixture
def test_auth_token() -> str:
    """Get test authentication token."""
    from tests.integration.test_config import TEST_AUTH_TOKEN
    return TEST_AUTH_TOKEN

