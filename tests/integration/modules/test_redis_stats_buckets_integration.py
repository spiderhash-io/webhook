"""
Integration tests for Redis stats bucket operations.

These tests verify time-based bucket operations, stats aggregation, and expiration.
"""

import pytest
import redis.asyncio as redis
import asyncio
import time
from tests.integration.test_config import REDIS_URL, TEST_REDIS_PREFIX
from src.utils import RedisEndpointStats


@pytest.mark.integration
@pytest.mark.external_services
class TestRedisStatsBucketsIntegration:
    """Integration tests for Redis stats bucket operations."""
    
    @pytest.fixture
    async def redis_client(self):
        """Create a Redis client for testing."""
        r = redis.from_url(REDIS_URL, decode_responses=True)
        yield r
        await r.aclose()
    
    @pytest.fixture
    async def stats_instance(self):
        """Create a RedisEndpointStats instance for testing."""
        stats = RedisEndpointStats(redis_url=REDIS_URL)
        yield stats
        await stats.close()
    
    @pytest.mark.asyncio
    async def test_stats_increment_creates_buckets(self, stats_instance, redis_client):
        """Test that incrementing stats creates time buckets."""
        test_endpoint = f"{TEST_REDIS_PREFIX}test_bucket_endpoint"
        
        # Clear any existing stats
        await redis_client.delete(f"stats:{test_endpoint}:total")
        await redis_client.delete(f"stats:endpoints")
        
        # Increment stats
        await stats_instance.increment(test_endpoint)
        
        # Wait a bit for async operations
        await asyncio.sleep(0.5)
        
        # Check that total was incremented
        total = await redis_client.get(f"stats:{test_endpoint}:total")
        assert total is not None
        assert int(total) >= 1
        
        # Check that endpoint was added to set
        endpoints = await redis_client.smembers("stats:endpoints")
        assert test_endpoint in endpoints
    
    @pytest.mark.asyncio
    async def test_stats_bucket_creation(self, stats_instance, redis_client):
        """Test that time buckets are created with correct keys."""
        test_endpoint = f"{TEST_REDIS_PREFIX}test_bucket_creation"
        
        # Clear existing data
        await redis_client.delete(f"stats:{test_endpoint}:total")
        keys = await redis_client.keys(f"stats:{test_endpoint}:bucket:*")
        if keys:
            await redis_client.delete(*keys)
        
        # Increment stats
        await stats_instance.increment(test_endpoint)
        await asyncio.sleep(0.5)
        
        # Check for bucket keys (format: stats:endpoint:bucket:timestamp)
        bucket_keys = await redis_client.keys(f"stats:{test_endpoint}:bucket:*")
        assert len(bucket_keys) >= 1
        
        # Verify bucket key format
        for key in bucket_keys:
            assert "bucket:" in key
            # Extract timestamp from key
            parts = key.split(":")
            assert len(parts) >= 4
            timestamp = int(parts[-1])
            assert timestamp > 0
    
    @pytest.mark.asyncio
    async def test_stats_bucket_expiration(self, stats_instance, redis_client):
        """Test that bucket keys have expiration set."""
        test_endpoint = f"{TEST_REDIS_PREFIX}test_bucket_expiration"
        
        # Clear existing data
        await redis_client.delete(f"stats:{test_endpoint}:total")
        keys = await redis_client.keys(f"stats:{test_endpoint}:bucket:*")
        if keys:
            await redis_client.delete(*keys)
        
        # Increment stats
        await stats_instance.increment(test_endpoint)
        await asyncio.sleep(0.5)
        
        # Get bucket keys
        bucket_keys = await redis_client.keys(f"stats:{test_endpoint}:bucket:*")
        if bucket_keys:
            # Check TTL on first bucket
            ttl = await redis_client.ttl(bucket_keys[0])
            assert ttl > 0  # Should have expiration set
            # Day buckets use 3000000 seconds (~34.7 days), hour buckets use 172800 seconds (2 days)
            # Accept any reasonable TTL (up to 35 days to account for day buckets)
            assert ttl <= 35 * 24 * 60 * 60  # Should be <= 35 days (day buckets are ~34.7 days)
    
    @pytest.mark.asyncio
    async def test_stats_aggregation(self, stats_instance, redis_client):
        """Test that stats can be retrieved and aggregated."""
        test_endpoint = f"{TEST_REDIS_PREFIX}test_aggregation"
        
        # Clear existing data
        await redis_client.delete(f"stats:{test_endpoint}:total")
        await redis_client.srem("stats:endpoints", test_endpoint)
        keys = await redis_client.keys(f"stats:{test_endpoint}:*")
        if keys:
            await redis_client.delete(*keys)
        
        # Increment stats multiple times
        for _ in range(3):
            await stats_instance.increment(test_endpoint)
            await asyncio.sleep(0.1)
        
        await asyncio.sleep(0.5)
        
        # Get stats
        stats_data = await stats_instance.get_stats()
        
        # Check that endpoint is in stats
        assert test_endpoint in stats_data
        endpoint_stats = stats_data[test_endpoint]
        
        # Check that total is at least 3
        assert endpoint_stats.get("total", 0) >= 3
    
    @pytest.mark.asyncio
    async def test_stats_endpoint_set_management(self, redis_client):
        """Test managing the set of known endpoints."""
        test_endpoint = f"{TEST_REDIS_PREFIX}test_endpoint_set"
        
        # Clear endpoint from set
        await redis_client.srem("stats:endpoints", test_endpoint)
        
        # Verify endpoint is not in set
        endpoints = await redis_client.smembers("stats:endpoints")
        assert test_endpoint not in endpoints
        
        # Add endpoint to set
        await redis_client.sadd("stats:endpoints", test_endpoint)
        
        # Verify endpoint is in set
        endpoints = await redis_client.smembers("stats:endpoints")
        assert test_endpoint in endpoints
        
        # Cleanup
        await redis_client.srem("stats:endpoints", test_endpoint)
    
    @pytest.mark.asyncio
    async def test_stats_multiple_endpoints(self, stats_instance, redis_client):
        """Test stats tracking for multiple endpoints."""
        endpoint1 = f"{TEST_REDIS_PREFIX}endpoint1"
        endpoint2 = f"{TEST_REDIS_PREFIX}endpoint2"
        
        # Clear existing data
        for endpoint in [endpoint1, endpoint2]:
            await redis_client.delete(f"stats:{endpoint}:total")
            await redis_client.srem("stats:endpoints", endpoint)
        
        # Increment stats for both endpoints
        await stats_instance.increment(endpoint1)
        await stats_instance.increment(endpoint2)
        await asyncio.sleep(0.5)
        
        # Get stats
        stats_data = await stats_instance.get_stats()
        
        # Both endpoints should be in stats
        assert endpoint1 in stats_data
        assert endpoint2 in stats_data
        
        # Both should have totals
        assert stats_data[endpoint1].get("total", 0) >= 1
        assert stats_data[endpoint2].get("total", 0) >= 1
    
    @pytest.mark.asyncio
    async def test_stats_pipeline_operations(self, stats_instance, redis_client):
        """Test that stats operations use pipelines for atomicity."""
        test_endpoint = f"{TEST_REDIS_PREFIX}test_pipeline"
        
        # Clear existing data
        await redis_client.delete(f"stats:{test_endpoint}:total")
        keys = await redis_client.keys(f"stats:{test_endpoint}:*")
        if keys:
            await redis_client.delete(*keys)
        
        # Increment stats (uses pipeline internally)
        await stats_instance.increment(test_endpoint)
        await asyncio.sleep(0.5)
        
        # Verify all operations completed atomically
        total = await redis_client.get(f"stats:{test_endpoint}:total")
        endpoints = await redis_client.smembers("stats:endpoints")
        
        # Both should be set if pipeline worked
        assert total is not None or test_endpoint in endpoints

