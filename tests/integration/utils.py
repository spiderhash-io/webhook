"""
Utility functions for integration tests.

Helper functions for making authenticated HTTP requests, waiting for async
operations, cleaning up test data, and checking service health.
"""

import asyncio
import httpx
import subprocess
import socket
import os
from typing import Optional, Dict, Any
from tests.integration.test_config import (
    REDIS_HOST,
    REDIS_PORT,
    RABBITMQ_HOST,
    RABBITMQ_PORT,
    CLICKHOUSE_HOST,
    CLICKHOUSE_PORT,
    CLICKHOUSE_HTTP_URL,
    KAFKA_HOST,
    KAFKA_PORT,
    API_BASE_URL,
)


def check_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a TCP port is open and accepting connections."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_redis_health() -> bool:
    """Check if Redis is accessible."""
    return check_port_open(REDIS_HOST, REDIS_PORT)


def check_rabbitmq_health() -> bool:
    """Check if RabbitMQ is accessible."""
    return check_port_open(RABBITMQ_HOST, RABBITMQ_PORT)


def check_clickhouse_health() -> bool:
    """Check if ClickHouse HTTP interface is accessible."""
    try:
        response = httpx.get(f"{CLICKHOUSE_HTTP_URL}/ping", timeout=2.0)
        return response.status_code == 200 and response.text.strip() in ["Ok", "Ok."]
    except Exception:
        return False


def check_kafka_health() -> bool:
    """Check if Kafka/Redpanda is accessible."""
    return check_port_open(KAFKA_HOST, KAFKA_PORT)


def check_api_health() -> bool:
    """Check if FastAPI server is accessible."""
    try:
        response = httpx.get(f"{API_BASE_URL}/", timeout=2.0)
        return response.status_code == 200
    except Exception:
        return False


def check_docker_services() -> Dict[str, bool]:
    """Check if Docker services are running using docker-compose."""
    try:
        # Try docker compose (v2) first, fallback to docker-compose (v1)
        # Use integration test docker-compose file
        compose_file = "tests/integration/config/docker-compose.yaml"
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", compose_file, "ps", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=5.0,
                cwd=os.path.join(os.path.dirname(__file__), "../..")
            )
        except FileNotFoundError:
            result = subprocess.run(
                ["docker-compose", "-f", compose_file, "ps", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=5.0,
                cwd=os.path.join(os.path.dirname(__file__), "../..")
            )
        if result.returncode != 0:
            # Fallback to port checks if docker compose ps fails
            return {
                "redis": check_redis_health(),
                "rabbitmq": check_rabbitmq_health(),
                "clickhouse": check_clickhouse_health(),
                "kafka": check_kafka_health(),
            }
        
        # Parse docker-compose output
        services = {}
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            import json
            try:
                service_info = json.loads(line)
                service_name = service_info.get("Service", "")
                status = service_info.get("State", "")
                if "redis" in service_name.lower():
                    services["redis"] = status == "running"
                elif "rabbitmq" in service_name.lower():
                    services["rabbitmq"] = status == "running"
                elif "clickhouse" in service_name.lower():
                    services["clickhouse"] = status == "running"
                elif "redpanda" in service_name.lower() or "kafka" in service_name.lower():
                    services["kafka"] = status == "running"
            except json.JSONDecodeError:
                continue
        
        # If we didn't find services in JSON format, try port checks as fallback
        if not services:
            return {
                "redis": check_redis_health(),
                "rabbitmq": check_rabbitmq_health(),
                "clickhouse": check_clickhouse_health(),
                "kafka": check_kafka_health(),
            }
        
        return {
            "redis": services.get("redis", False),
            "rabbitmq": services.get("rabbitmq", False),
            "clickhouse": services.get("clickhouse", False),
            "kafka": services.get("kafka", False),
        }
    except Exception:
        # Fallback to port checks
        return {
            "redis": check_redis_health(),
            "rabbitmq": check_rabbitmq_health(),
            "clickhouse": check_clickhouse_health(),
            "kafka": check_kafka_health(),
        }


async def wait_for_service(
    check_func,
    timeout: float = 30.0,
    interval: float = 1.0,
    service_name: str = "service"
) -> bool:
    """Wait for a service to become available."""
    elapsed = 0.0
    while elapsed < timeout:
        if check_func():
            return True
        await asyncio.sleep(interval)
        elapsed += interval
    return False


async def make_authenticated_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    auth_token: Optional[str] = None,
    **kwargs
) -> httpx.Response:
    """Make an authenticated HTTP request."""
    headers = kwargs.pop("headers", {})
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    return await client.request(method, url, headers=headers, **kwargs)


async def cleanup_redis_keys(prefix: str = "test:integration:") -> None:
    """Clean up Redis keys with a given prefix."""
    try:
        import redis.asyncio as redis
        from tests.integration.test_config import REDIS_URL
        
        r = redis.from_url(REDIS_URL, decode_responses=True)
        keys = await r.keys(f"{prefix}*")
        if keys:
            await r.delete(*keys)
        await r.aclose()
    except Exception:
        pass  # Ignore cleanup errors


def get_test_webhook_config(module: str = "log") -> Dict[str, Any]:
    """Get a test webhook configuration."""
    from tests.integration.test_config import TEST_WEBHOOK_ID, TEST_AUTH_TOKEN
    
    config = {
        "data_type": "json",
        "module": module,
        "authorization": f"Bearer {TEST_AUTH_TOKEN}",
    }
    
    if module == "rabbitmq":
        config["queue_name"] = f"test_integration_queue"
        config["connection"] = "rabbitmq_test"
    elif module == "redis-rq":
        config["function_name"] = "test_function"
        config["connection"] = "redis_test"
    elif module == "clickhouse":
        config["connection"] = "clickhouse_test"
        config["module-config"] = {
            "table": "test_integration_logs"
        }
    
    return config

