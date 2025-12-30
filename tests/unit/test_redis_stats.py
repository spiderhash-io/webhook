import pytest
import asyncio
from src.utils import RedisEndpointStats
import time
from unittest.mock import MagicMock, patch, AsyncMock

@pytest.mark.asyncio
async def test_redis_stats_increment():
    # Mock Redis client
    mock_redis = MagicMock()
    # Pipeline context manager needs to be async
    mock_pipeline = AsyncMock()
    mock_redis.pipeline.return_value.__aenter__.return_value = mock_pipeline
    
    # Setup patch
    with patch('redis.asyncio.from_url', return_value=mock_redis):
        stats = RedisEndpointStats()
        
        # Test increment
        await stats.increment("test_endpoint")
        
        # Verify pipeline calls
        assert mock_pipeline.sadd.called
        assert mock_pipeline.incr.call_count >= 2 # total + bucket(s)
        assert mock_pipeline.expire.called
        assert mock_pipeline.execute.called
        
        # Verify specific calls
        mock_pipeline.sadd.assert_called_with("stats:endpoints", "test_endpoint")
        mock_pipeline.incr.assert_any_call("stats:test_endpoint:total")

@pytest.mark.asyncio
async def test_redis_stats_get_stats():
    # Mock Redis client
    mock_redis = MagicMock()
    
    # Setup data for get_stats
    # endpoints - needs to be awaitable
    mock_redis.smembers = AsyncMock(return_value={"test_endpoint"})
    
    # total - needs to be awaitable
    mock_redis.get = AsyncMock(return_value="100")
    
    # mget results (buckets) - needs to be awaitable
    # We need to return enough zeros or values for the mget call
    mock_redis.mget = AsyncMock(return_value=["1"] * 200)
    
    with patch('redis.asyncio.from_url', return_value=mock_redis):
        stats = RedisEndpointStats()
        
        result = await stats.get_stats()
        
        assert "test_endpoint" in result
        assert result["test_endpoint"]["total"] == 100
        # Since we returned "1" for all buckets:
        # minute (1 bucket) = 1
        # 5_minutes (5 buckets) = 5
        assert result["test_endpoint"]["minute"] == 1
        assert result["test_endpoint"]["5_minutes"] == 5

@pytest.mark.asyncio
async def test_redis_stats_persistence_simulation():
    mock_redis = MagicMock()
    
    with patch('redis.asyncio.from_url', return_value=mock_redis):
        stats1 = RedisEndpointStats()
        # Mock pipeline for increment
        mock_pipeline = AsyncMock()
        mock_redis.pipeline.return_value.__aenter__.return_value = mock_pipeline
        
        await stats1.increment("test_endpoint")
        
        stats2 = RedisEndpointStats()
        assert stats1.redis == stats2.redis
