import pytest
import asyncio
from src.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_allows_within_limit():
    """Test that requests within limit are allowed."""
    limiter = RateLimiter()
    
    # Allow 5 requests per 10 seconds
    for i in range(5):
        is_allowed, message = await limiter.is_allowed("test_webhook", 5, 10)
        assert is_allowed is True
        assert "allowed" in message.lower()


@pytest.mark.asyncio
async def test_rate_limiter_blocks_over_limit():
    """Test that requests over limit are blocked."""
    limiter = RateLimiter()
    
    # Allow 3 requests per 10 seconds
    for i in range(3):
        is_allowed, _ = await limiter.is_allowed("test_webhook_2", 3, 10)
        assert is_allowed is True
    
    # 4th request should be blocked
    is_allowed, message = await limiter.is_allowed("test_webhook_2", 3, 10)
    assert is_allowed is False
    assert "Rate limit exceeded" in message


@pytest.mark.asyncio
async def test_rate_limiter_sliding_window():
    """Test that rate limiter uses sliding window correctly."""
    limiter = RateLimiter()
    
    # Allow 2 requests per 1 second
    is_allowed, _ = await limiter.is_allowed("test_webhook_3", 2, 1)
    assert is_allowed is True
    
    is_allowed, _ = await limiter.is_allowed("test_webhook_3", 2, 1)
    assert is_allowed is True
    
    # 3rd request should be blocked
    is_allowed, _ = await limiter.is_allowed("test_webhook_3", 2, 1)
    assert is_allowed is False
    
    # Wait for window to pass
    await asyncio.sleep(1.1)
    
    # Should be allowed again
    is_allowed, _ = await limiter.is_allowed("test_webhook_3", 2, 1)
    assert is_allowed is True


@pytest.mark.asyncio
async def test_rate_limiter_different_webhooks():
    """Test that different webhooks have separate limits."""
    limiter = RateLimiter()
    
    # Webhook A: 2 requests
    for i in range(2):
        is_allowed, _ = await limiter.is_allowed("webhook_a", 2, 10)
        assert is_allowed is True
    
    # Webhook A: 3rd request blocked
    is_allowed, _ = await limiter.is_allowed("webhook_a", 2, 10)
    assert is_allowed is False
    
    # Webhook B: should still be allowed
    is_allowed, _ = await limiter.is_allowed("webhook_b", 2, 10)
    assert is_allowed is True


@pytest.mark.asyncio
async def test_rate_limiter_cleanup():
    """Test that cleanup removes old entries."""
    limiter = RateLimiter()
    
    # Add some requests
    await limiter.is_allowed("old_webhook", 10, 1)
    
    # Wait for entries to become old
    await asyncio.sleep(1.1)
    
    # Cleanup with 1 second max age
    await limiter.cleanup_old_entries(max_age_seconds=1)
    
    # Check that old webhook was removed
    assert "old_webhook" not in limiter.requests or len(limiter.requests["old_webhook"]) == 0


# Integration test with validator
from src.validators import RateLimitValidator


@pytest.mark.asyncio
async def test_rate_limit_validator():
    """Test RateLimitValidator."""
    config = {
        "rate_limit": {
            "max_requests": 3,
            "window_seconds": 10
        }
    }
    
    validator = RateLimitValidator(config, "test_webhook_validator")
    
    # First 3 requests should pass
    for i in range(3):
        is_valid, message = await validator.validate({}, b"")
        assert is_valid is True
    
    # 4th request should fail
    is_valid, message = await validator.validate({}, b"")
    assert is_valid is False
    assert "Rate limit exceeded" in message


@pytest.mark.asyncio
async def test_rate_limit_validator_no_config():
    """Test RateLimitValidator with no rate limit configured."""
    config = {}
    
    validator = RateLimitValidator(config, "test_webhook_no_limit")
    
    # Should always pass when no rate limit configured
    for i in range(10):
        is_valid, message = await validator.validate({}, b"")
        assert is_valid is True
        assert "No rate limit" in message
