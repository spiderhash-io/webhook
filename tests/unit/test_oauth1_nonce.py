"""
Security tests for OAuth 1.0 nonce validation.
Tests that nonce tracking prevents replay attacks.
"""

import pytest
import time
import asyncio
from src.validators import OAuth1Validator, OAuth1NonceTracker


class TestOAuth1NonceValidation:
    """Test suite for OAuth 1.0 nonce validation."""

    @pytest.fixture
    def validator(self):
        """Create OAuth1Validator instance."""
        config = {
            "oauth1": {
                "consumer_key": "test_consumer_key",
                "consumer_secret": "test_consumer_secret",
                "verify_nonce": True,
                "verify_timestamp": True,
                "timestamp_window": 300,
            }
        }
        return OAuth1Validator(config)

    @pytest.fixture
    def nonce_tracker(self):
        """Create OAuth1NonceTracker instance."""
        return OAuth1NonceTracker(max_age_seconds=600)

    @pytest.mark.asyncio
    async def test_nonce_validation_enabled(self, validator):
        """Test that nonce validation is enabled by default."""
        config = {
            "oauth1": {
                "consumer_key": "test_consumer_key",
                "consumer_secret": "test_consumer_secret",
                "verify_timestamp": False,  # Disable timestamp to test nonce
            }
        }
        validator = OAuth1Validator(config)

        # Missing nonce should fail
        headers = {
            "authorization": 'OAuth oauth_consumer_key="test_consumer_key", oauth_signature_method="HMAC-SHA1", oauth_signature="invalid"'
        }
        is_valid, message = await validator.validate(headers, b"{}")
        assert not is_valid
        assert "oauth_nonce" in message.lower()

    @pytest.mark.asyncio
    async def test_nonce_validation_disabled(self, validator):
        """Test that nonce validation can be disabled."""
        config = {
            "oauth1": {
                "consumer_key": "test_consumer_key",
                "consumer_secret": "test_consumer_secret",
                "verify_nonce": False,
                "verify_timestamp": False,  # Disable timestamp to test nonce
            }
        }
        validator = OAuth1Validator(config)

        # Missing nonce should be allowed when disabled
        headers = {
            "authorization": 'OAuth oauth_consumer_key="test_consumer_key", oauth_signature_method="HMAC-SHA1", oauth_signature="invalid"'
        }
        # Will fail on signature, but not on nonce
        is_valid, message = await validator.validate(headers, b"{}")
        assert not is_valid
        assert "oauth_nonce" not in message.lower()
        assert "signature" in message.lower()

    @pytest.mark.asyncio
    async def test_nonce_tracker_accepts_new_nonce(self, nonce_tracker):
        """Test that nonce tracker accepts new nonces."""
        nonce = "test_nonce_123"
        timestamp = int(time.time())
        timestamp_window = 300

        is_valid, message = await nonce_tracker.check_and_store_nonce(
            nonce, timestamp, timestamp_window
        )
        assert is_valid
        assert "valid" in message.lower()

    @pytest.mark.asyncio
    async def test_nonce_tracker_rejects_duplicate_nonce(self, nonce_tracker):
        """Test that nonce tracker rejects duplicate nonces."""
        nonce = "test_nonce_456"
        timestamp = int(time.time())
        timestamp_window = 300

        # First use - should succeed
        is_valid, message = await nonce_tracker.check_and_store_nonce(
            nonce, timestamp, timestamp_window
        )
        assert is_valid

        # Second use - should fail (replay attack)
        is_valid, message = await nonce_tracker.check_and_store_nonce(
            nonce, timestamp, timestamp_window
        )
        assert not is_valid
        assert "replay" in message.lower() or "already been used" in message.lower()

    @pytest.mark.asyncio
    async def test_nonce_tracker_rejects_empty_nonce(self, validator):
        """Test that empty nonce is rejected."""
        config = {
            "oauth1": {
                "consumer_key": "test_consumer_key",
                "consumer_secret": "test_consumer_secret",
                "verify_timestamp": False,  # Disable timestamp to test nonce
            }
        }
        validator = OAuth1Validator(config)

        headers = {
            "authorization": 'OAuth oauth_consumer_key="test_consumer_key", oauth_signature_method="HMAC-SHA1", oauth_signature="invalid", oauth_nonce=""'
        }
        is_valid, message = await validator.validate(headers, b"{}")
        assert not is_valid
        assert "nonce" in message.lower()

    @pytest.mark.asyncio
    async def test_nonce_tracker_rejects_whitespace_nonce(self, validator):
        """Test that whitespace-only nonce is rejected."""
        config = {
            "oauth1": {
                "consumer_key": "test_consumer_key",
                "consumer_secret": "test_consumer_secret",
                "verify_timestamp": False,  # Disable timestamp to test nonce
            }
        }
        validator = OAuth1Validator(config)

        headers = {
            "authorization": 'OAuth oauth_consumer_key="test_consumer_key", oauth_signature_method="HMAC-SHA1", oauth_signature="invalid", oauth_nonce="   "'
        }
        is_valid, message = await validator.validate(headers, b"{}")
        assert not is_valid
        assert "nonce" in message.lower()

    @pytest.mark.asyncio
    async def test_nonce_tracker_expires_old_nonces(self, nonce_tracker):
        """Test that expired nonces are cleaned up and can be reused."""
        nonce = "test_nonce_expired"
        old_timestamp = int(time.time()) - 1000  # 1000 seconds ago
        timestamp_window = 300

        # Use nonce with old timestamp
        is_valid, message = await nonce_tracker.check_and_store_nonce(
            nonce, old_timestamp, timestamp_window
        )
        assert is_valid

        # Wait a bit and trigger cleanup
        await asyncio.sleep(0.1)

        # Use same nonce again - should fail (not expired yet due to buffer)
        # Actually, expiration is timestamp + window + 60s buffer
        # So old_timestamp + 300 + 60 = old_timestamp + 360
        # If current_time > old_timestamp + 360, it should be expired
        # But we just set it, so it might not be expired yet

        # Let's use a very old timestamp to ensure expiration
        very_old_timestamp = int(time.time()) - 2000  # 2000 seconds ago
        expired_nonce = "test_nonce_very_old"
        is_valid, message = await nonce_tracker.check_and_store_nonce(
            expired_nonce, very_old_timestamp, timestamp_window
        )
        assert is_valid

        # Manually trigger cleanup
        current_time = time.time()
        nonce_tracker._cleanup_expired_nonces(current_time)

        # Now try to use the expired nonce again - should succeed (expired, so can reuse)
        is_valid, message = await nonce_tracker.check_and_store_nonce(
            expired_nonce, int(time.time()), timestamp_window
        )
        assert is_valid  # Should succeed because old nonce was expired and removed

    @pytest.mark.asyncio
    async def test_nonce_tracker_multiple_nonces(self, nonce_tracker):
        """Test that multiple different nonces can be stored."""
        timestamp = int(time.time())
        timestamp_window = 300

        # Store multiple nonces
        for i in range(10):
            nonce = f"test_nonce_{i}"
            is_valid, message = await nonce_tracker.check_and_store_nonce(
                nonce, timestamp, timestamp_window
            )
            assert is_valid

        # All should be stored
        stats = await nonce_tracker.get_stats()
        assert stats["total_nonces"] >= 10

    @pytest.mark.asyncio
    async def test_nonce_tracker_stats(self, nonce_tracker):
        """Test that nonce tracker provides statistics."""
        timestamp = int(time.time())
        timestamp_window = 300

        # Store a nonce
        await nonce_tracker.check_and_store_nonce(
            "test_nonce_stats", timestamp, timestamp_window
        )

        # Get stats
        stats = await nonce_tracker.get_stats()
        assert "total_nonces" in stats
        assert "max_age_seconds" in stats
        assert stats["total_nonces"] >= 1
        assert stats["max_age_seconds"] == 600

    @pytest.mark.asyncio
    async def test_nonce_without_timestamp(self, nonce_tracker):
        """Test that nonce works even when timestamp validation is disabled."""
        # Use current time as timestamp
        timestamp = int(time.time())
        timestamp_window = 300

        nonce = "test_nonce_no_timestamp"
        is_valid, message = await nonce_tracker.check_and_store_nonce(
            nonce, timestamp, timestamp_window
        )
        assert is_valid

        # Try to reuse - should fail
        is_valid, message = await nonce_tracker.check_and_store_nonce(
            nonce, timestamp, timestamp_window
        )
        assert not is_valid

    @pytest.mark.asyncio
    async def test_nonce_tracker_cleanup_interval(self, nonce_tracker):
        """Test that cleanup happens periodically."""
        timestamp = int(time.time())
        timestamp_window = 300

        # Store a nonce
        await nonce_tracker.check_and_store_nonce(
            "test_nonce_cleanup", timestamp, timestamp_window
        )

        # Manually trigger cleanup
        current_time = time.time()
        initial_count = len(nonce_tracker.nonces)
        nonce_tracker._cleanup_expired_nonces(current_time)

        # Count should not increase (no expired nonces yet)
        assert len(nonce_tracker.nonces) == initial_count
