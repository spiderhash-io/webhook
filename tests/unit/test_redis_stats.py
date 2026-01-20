import pytest
import asyncio
from src.utils import RedisEndpointStats
import time
from unittest.mock import MagicMock, patch, AsyncMock


@pytest.mark.asyncio
async def test_redis_stats_increment():
    # Mock Redis client
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()

    # Mock Lua script
    mock_script = AsyncMock()
    mock_redis.register_script.return_value = mock_script

    # Setup patch
    with patch("redis.asyncio.from_url", return_value=mock_redis):
        stats = RedisEndpointStats()

        # Test increment
        await stats.increment("test_endpoint")

        # Verify script registration and call
        assert mock_redis.register_script.called
        assert mock_script.called

        # Verify arguments passed to script
        args, kwargs = mock_script.call_args
        # kwargs['args'] should contain endpoint and timestamp
        script_args = kwargs.get("args", [])
        assert script_args[0] == "test_endpoint"
        assert isinstance(script_args[1], int)


@pytest.mark.asyncio
async def test_redis_stats_get_stats():
    # Mock Redis client
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()

    # Setup data for get_stats
    # endpoints - needs to be awaitable
    mock_redis.smembers = AsyncMock(return_value={"test_endpoint"})

    # total in Hash - needs to be awaitable
    mock_redis.hget = AsyncMock(return_value="100")

    # mget results (buckets) - needs to be awaitable
    mock_redis.mget = AsyncMock(return_value=["1"] * 200)

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        stats = RedisEndpointStats()

        result = await stats.get_stats()

        assert "test_endpoint" in result
        assert result["test_endpoint"]["total"] == 100
        # Since we returned "1" for all buckets:
        # minute (1 bucket) = 1
        # 5_minutes (5 buckets) = 5
        assert result["test_endpoint"]["minute"] == 1
        assert result["test_endpoint"]["5_minutes"] == 5

        # Verify it used HGET
        mock_redis.hget.assert_called_with("stats:totals", "test_endpoint")


@pytest.mark.asyncio
async def test_redis_stats_persistence_simulation():
    mock_redis = MagicMock()
    mock_redis.ping = AsyncMock()
    mock_script = AsyncMock()
    mock_redis.register_script.return_value = mock_script

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        stats1 = RedisEndpointStats()
        await stats1.increment("test_endpoint")

        stats2 = RedisEndpointStats()
        assert stats1.redis == stats2.redis
