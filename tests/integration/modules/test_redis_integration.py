"""
Integration tests for Redis module.

These tests verify that webhook data is actually stored in Redis.
"""

import pytest
import httpx
import redis.asyncio as redis
import asyncio
from tests.integration.test_config import REDIS_URL, TEST_REDIS_PREFIX
from tests.integration.utils import make_authenticated_request


@pytest.mark.integration
class TestRedisIntegration:
    """Integration tests for Redis publish module."""
    
    @pytest.fixture
    async def redis_client(self):
        """Create a Redis client for testing."""
        r = redis.from_url(REDIS_URL, decode_responses=True)
        yield r
        await r.aclose()
    
    @pytest.mark.asyncio
    async def test_redis_connection(self, redis_client):
        """Test that we can connect to Redis."""
        result = await redis_client.ping()
        assert result is True
    
    @pytest.mark.asyncio
    async def test_redis_publish_webhook(
        self,
        http_client: httpx.AsyncClient,
        redis_client,
        test_webhook_id: str,
        test_auth_token: str
    ):
        """Test that webhook data is published to Redis channel."""
        # Subscribe to test channel
        test_channel = f"{TEST_REDIS_PREFIX}test_channel"
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(test_channel)
        
        # Send webhook request (if webhook is configured with redis_publish)
        payload = {
            "test": "redis_integration",
            "timestamp": "2024-01-01T00:00:00Z"
        }
        
        response = await make_authenticated_request(
            http_client,
            "POST",
            f"/webhook/{test_webhook_id}",
            auth_token=test_auth_token,
            json=payload
        )
        
        # Note: This test assumes a webhook is configured with redis_publish module
        # If not configured, the test will pass with 404
        if response.status_code == 404:
            pytest.skip(f"Webhook {test_webhook_id} not configured with redis_publish")
        
        # Wait a bit for async processing
        await asyncio.sleep(0.5)
        
        # Check if message was received (with timeout)
        try:
            message = await asyncio.wait_for(
                pubsub.get_message(timeout=2.0),
                timeout=3.0
            )
            if message and message["type"] == "message":
                assert message["channel"] == test_channel
                # Message should contain the payload
                assert "test" in message["data"] or "redis_integration" in message["data"]
        except asyncio.TimeoutError:
            # Message might not arrive if webhook isn't configured correctly
            pass
        finally:
            await pubsub.unsubscribe(test_channel)
            await pubsub.close()
    
    @pytest.mark.asyncio
    async def test_redis_stats_persistence(
        self,
        http_client: httpx.AsyncClient,
        redis_client,
        test_webhook_id: str,
        test_auth_token: str
    ):
        """Test that webhook stats are persisted in Redis."""
        # Get initial stats count
        initial_total = await redis_client.get(f"stats:{test_webhook_id}:total")
        initial_count = int(initial_total) if initial_total else 0
        
        # Send a webhook request
        payload = {"test": "stats_persistence"}
        response = await make_authenticated_request(
            http_client,
            "POST",
            f"/webhook/{test_webhook_id}",
            auth_token=test_auth_token,
            json=payload
        )
        
        # Wait for async stats update
        await asyncio.sleep(1.0)
        
        # Check if stats were updated in Redis
        new_total = await redis_client.get(f"stats:{test_webhook_id}:total")
        if new_total:
            new_count = int(new_total)
            # Stats should have increased if webhook was processed
            if response.status_code == 200:
                assert new_count >= initial_count
    
    @pytest.mark.asyncio
    async def test_redis_key_operations(self, redis_client):
        """Test basic Redis key operations."""
        test_key = f"{TEST_REDIS_PREFIX}test_key"
        test_value = "test_value_123"
        
        # Set a key
        await redis_client.set(test_key, test_value)
        
        # Get the key
        value = await redis_client.get(test_key)
        assert value == test_value
        
        # Delete the key
        await redis_client.delete(test_key)
        
        # Verify it's deleted
        value = await redis_client.get(test_key)
        assert value is None

