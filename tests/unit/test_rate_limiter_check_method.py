"""
Security tests for RateLimiter.check_rate_limit method.
Tests that the method exists and works correctly to prevent runtime errors.
"""
import pytest
import asyncio
from src.rate_limiter import RateLimiter


class TestRateLimiterCheckMethod:
    """Test suite for RateLimiter.check_rate_limit method."""
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_method_exists(self):
        """Test that check_rate_limit method exists on RateLimiter."""
        rate_limiter = RateLimiter()
        
        # Method should exist
        assert hasattr(rate_limiter, 'check_rate_limit')
        assert callable(getattr(rate_limiter, 'check_rate_limit'))
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_allows_request(self):
        """Test that check_rate_limit allows requests within limit."""
        rate_limiter = RateLimiter()
        
        # First request should be allowed
        is_allowed, remaining = await rate_limiter.check_rate_limit(
            "test_key",
            max_requests=10,
            window_seconds=60
        )
        
        assert is_allowed is True
        assert remaining == 9  # 10 - 1 = 9 remaining
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_returns_remaining(self):
        """Test that check_rate_limit returns correct remaining count."""
        rate_limiter = RateLimiter()
        
        # Make 3 requests
        for i in range(3):
            is_allowed, remaining = await rate_limiter.check_rate_limit(
                "test_key",
                max_requests=10,
                window_seconds=60
            )
            assert is_allowed is True
            assert remaining == 10 - (i + 1)
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_blocks_exceeding_requests(self):
        """Test that check_rate_limit blocks requests exceeding limit."""
        rate_limiter = RateLimiter()
        
        max_requests = 3
        window_seconds = 60
        
        # Make requests up to limit
        for i in range(max_requests):
            is_allowed, remaining = await rate_limiter.check_rate_limit(
                "test_key",
                max_requests=max_requests,
                window_seconds=window_seconds
            )
            assert is_allowed is True
        
        # Next request should be blocked
        is_allowed, remaining = await rate_limiter.check_rate_limit(
            "test_key",
            max_requests=max_requests,
            window_seconds=window_seconds
        )
        
        assert is_allowed is False
        assert remaining == 0
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_different_keys(self):
        """Test that check_rate_limit works with different keys independently."""
        rate_limiter = RateLimiter()
        
        # Use different keys
        is_allowed_1, remaining_1 = await rate_limiter.check_rate_limit(
            "key1",
            max_requests=2,
            window_seconds=60
        )
        
        is_allowed_2, remaining_2 = await rate_limiter.check_rate_limit(
            "key2",
            max_requests=2,
            window_seconds=60
        )
        
        assert is_allowed_1 is True
        assert is_allowed_2 is True
        assert remaining_1 == 1
        assert remaining_2 == 1
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_window_expiration(self):
        """Test that check_rate_limit respects time windows."""
        rate_limiter = RateLimiter()
        
        max_requests = 2
        window_seconds = 1  # 1 second window
        
        # Make requests up to limit
        for i in range(max_requests):
            is_allowed, remaining = await rate_limiter.check_rate_limit(
                "test_key",
                max_requests=max_requests,
                window_seconds=window_seconds
            )
            assert is_allowed is True
        
        # Next request should be blocked
        is_allowed, remaining = await rate_limiter.check_rate_limit(
            "test_key",
            max_requests=max_requests,
            window_seconds=window_seconds
        )
        assert is_allowed is False
        
        # Wait for window to expire
        await asyncio.sleep(1.1)
        
        # Request should be allowed again
        is_allowed, remaining = await rate_limiter.check_rate_limit(
            "test_key",
            max_requests=max_requests,
            window_seconds=window_seconds
        )
        assert is_allowed is True
        assert remaining == 1
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_zero_remaining_when_blocked(self):
        """Test that remaining is 0 when rate limited."""
        rate_limiter = RateLimiter()
        
        max_requests = 1
        window_seconds = 60
        
        # First request allowed
        is_allowed, remaining = await rate_limiter.check_rate_limit(
            "test_key",
            max_requests=max_requests,
            window_seconds=window_seconds
        )
        assert is_allowed is True
        assert remaining == 0  # 1 - 1 = 0
        
        # Second request blocked
        is_allowed, remaining = await rate_limiter.check_rate_limit(
            "test_key",
            max_requests=max_requests,
            window_seconds=window_seconds
        )
        assert is_allowed is False
        assert remaining == 0
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_concurrent_requests(self):
        """Test that check_rate_limit handles concurrent requests correctly."""
        rate_limiter = RateLimiter()
        
        max_requests = 5
        window_seconds = 60
        
        # Make concurrent requests
        tasks = []
        for i in range(10):
            task = rate_limiter.check_rate_limit(
                "test_key",
                max_requests=max_requests,
                window_seconds=window_seconds
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # Count allowed and blocked
        allowed_count = sum(1 for is_allowed, _ in results if is_allowed)
        blocked_count = sum(1 for is_allowed, _ in results if not is_allowed)
        
        # Should have exactly max_requests allowed
        assert allowed_count == max_requests
        assert blocked_count == 10 - max_requests
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_return_type(self):
        """Test that check_rate_limit returns correct types."""
        rate_limiter = RateLimiter()
        
        is_allowed, remaining = await rate_limiter.check_rate_limit(
            "test_key",
            max_requests=10,
            window_seconds=60
        )
        
        # Should return tuple of (bool, int)
        assert isinstance(is_allowed, bool)
        assert isinstance(remaining, int)
        assert remaining >= 0
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_stats_endpoint_usage(self):
        """Test that check_rate_limit works as expected for stats endpoint usage."""
        rate_limiter = RateLimiter()
        
        # Simulate stats endpoint usage
        client_ip = "192.168.1.100"
        stats_key = f"stats_endpoint:{client_ip}"
        stats_rate_limit = 10
        window_seconds = 60
        
        # Make requests
        for i in range(5):
            is_allowed, remaining = await rate_limiter.check_rate_limit(
                stats_key,
                max_requests=stats_rate_limit,
                window_seconds=window_seconds
            )
            assert is_allowed is True
            assert remaining == stats_rate_limit - (i + 1)
        
        # Verify remaining is correct (after 5 requests, 5 should remain)
        # Note: The last check_rate_limit call above already added a request, so we have 5 requests total
        # The next call will add the 6th request, leaving 4 remaining
        is_allowed, remaining = await rate_limiter.check_rate_limit(
            stats_key,
            max_requests=stats_rate_limit,
            window_seconds=window_seconds
        )
        assert is_allowed is True
        assert remaining == 4  # 10 - 6 = 4 remaining (6th request was just added)

