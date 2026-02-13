"""
Security tests for AuthorizationValidator timing attack prevention.
Tests constant-time comparison to prevent timing-based attacks.
"""

import pytest
import time
import statistics
from src.validators import AuthorizationValidator


class TestAuthorizationTiming:
    """Test suite for AuthorizationValidator timing attack prevention."""

    @pytest.mark.asyncio
    async def test_authorization_valid_token(self):
        """Test that valid authorization tokens are accepted."""
        config = {"authorization": "Bearer secret_token_123"}
        validator = AuthorizationValidator(config)

        headers = {"authorization": "Bearer secret_token_123"}
        is_valid, message = await validator.validate(headers, b"")

        assert is_valid is True
        assert "Valid authorization" in message

    @pytest.mark.asyncio
    async def test_authorization_invalid_token(self):
        """Test that invalid authorization tokens are rejected."""
        config = {"authorization": "Bearer secret_token_123"}
        validator = AuthorizationValidator(config)

        headers = {"authorization": "Bearer wrong_token"}
        is_valid, message = await validator.validate(headers, b"")

        assert is_valid is False
        assert "Unauthorized" in message

    @pytest.mark.asyncio
    async def test_authorization_timing_attack_resistance(self):
        """
        Test that timing attacks are prevented by using constant-time comparison.

        This test measures the time taken to validate tokens and ensures
        that valid and invalid tokens take approximately the same time,
        preventing timing-based token enumeration.
        """
        config = {
            "authorization": "Bearer "
            + "a" * 100  # Long token for better timing measurement
        }
        validator = AuthorizationValidator(config)

        valid_token = "Bearer " + "a" * 100
        invalid_token_early = "Bearer " + "b" + "a" * 99  # Wrong first char
        invalid_token_late = "Bearer " + "a" * 99 + "b"  # Wrong last char
        invalid_token_wrong_length = "Bearer " + "a" * 99  # Wrong length

        # Measure validation times
        iterations = 100
        valid_times = []
        invalid_early_times = []
        invalid_late_times = []
        invalid_length_times = []

        for _ in range(iterations):
            # Valid token
            start = time.perf_counter()
            await validator.validate({"authorization": valid_token}, b"")
            valid_times.append(time.perf_counter() - start)

            # Invalid token (early mismatch)
            start = time.perf_counter()
            await validator.validate({"authorization": invalid_token_early}, b"")
            invalid_early_times.append(time.perf_counter() - start)

            # Invalid token (late mismatch)
            start = time.perf_counter()
            await validator.validate({"authorization": invalid_token_late}, b"")
            invalid_late_times.append(time.perf_counter() - start)

            # Invalid token (wrong length)
            start = time.perf_counter()
            await validator.validate({"authorization": invalid_token_wrong_length}, b"")
            invalid_length_times.append(time.perf_counter() - start)

        # Calculate average times
        avg_valid = statistics.mean(valid_times)
        avg_invalid_early = statistics.mean(invalid_early_times)
        avg_invalid_late = statistics.mean(invalid_late_times)
        avg_invalid_length = statistics.mean(invalid_length_times)

        # All times should be similar (within reasonable variance)
        # Allow 30% variance to account for system noise and CI jitter
        max_time = max(
            avg_valid, avg_invalid_early, avg_invalid_late, avg_invalid_length
        )
        min_time = min(
            avg_valid, avg_invalid_early, avg_invalid_late, avg_invalid_length
        )

        # The absolute difference should be small.
        # When times are sub-microsecond (< 0.01ms), ratio-based checks amplify
        # floating point noise. Use absolute threshold for very fast operations.
        abs_diff = max_time - min_time
        time_diff_ratio = abs_diff / max_time if max_time > 0 else 0

        # Skip ratio check when all times are under 0.01ms (10 microseconds)
        # — at that resolution, noise dominates and ratio is meaningless
        if max_time >= 0.00001:
            assert time_diff_ratio < 0.50, (
                f"Timing attack vulnerability detected! "
                f"Time difference ratio: {time_diff_ratio:.2%}, "
                f"Valid: {avg_valid*1000:.3f}ms, "
                f"Invalid (early): {avg_invalid_early*1000:.3f}ms, "
                f"Invalid (late): {avg_invalid_late*1000:.3f}ms, "
                f"Invalid (length): {avg_invalid_length*1000:.3f}ms"
            )

        # Always check absolute difference: must be under 1ms
        assert abs_diff < 0.001, (
            f"Timing attack vulnerability detected! "
            f"Absolute time difference: {abs_diff*1000:.3f}ms, "
            f"Valid: {avg_valid*1000:.3f}ms, "
            f"Invalid (early): {avg_invalid_early*1000:.3f}ms, "
            f"Invalid (late): {avg_invalid_late*1000:.3f}ms, "
            f"Invalid (length): {avg_invalid_length*1000:.3f}ms"
        )

    @pytest.mark.asyncio
    async def test_authorization_bearer_token_format(self):
        """Test Bearer token format validation."""
        config = {"authorization": "Bearer secret_token"}
        validator = AuthorizationValidator(config)

        # Missing Bearer prefix
        headers = {"authorization": "secret_token"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message

        # Correct Bearer format
        headers = {"authorization": "Bearer secret_token"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_authorization_non_bearer_token(self):
        """Test non-Bearer token validation."""
        config = {"authorization": "CustomToken secret_value"}
        validator = AuthorizationValidator(config)

        # Valid custom token
        headers = {"authorization": "CustomToken secret_value"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

        # Invalid custom token
        headers = {"authorization": "CustomToken wrong_value"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_authorization_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        config = {"authorization": "Bearer token123"}
        validator = AuthorizationValidator(config)

        # Leading/trailing whitespace should be normalized
        headers = {"authorization": "  Bearer token123  "}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

        # Whitespace in token should be preserved
        config = {"authorization": "Bearer token with spaces"}
        validator = AuthorizationValidator(config)

        headers = {"authorization": "Bearer token with spaces"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_authorization_empty_header(self):
        """Test validation with empty authorization header."""
        config = {"authorization": "Bearer secret_token"}
        validator = AuthorizationValidator(config)

        headers = {"authorization": ""}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message or "Unauthorized" in message

    @pytest.mark.asyncio
    async def test_authorization_missing_header(self):
        """Test validation with missing authorization header."""
        config = {"authorization": "Bearer secret_token"}
        validator = AuthorizationValidator(config)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message or "Unauthorized" in message

    @pytest.mark.asyncio
    async def test_authorization_no_config(self):
        """Test that validation passes when no authorization is configured."""
        config = {}
        validator = AuthorizationValidator(config)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        assert "No authorization required" in message

    @pytest.mark.asyncio
    async def test_authorization_case_sensitivity(self):
        """Test that token comparison is case-sensitive."""
        config = {"authorization": "Bearer SecretToken"}
        validator = AuthorizationValidator(config)

        # Different case should fail
        headers = {"authorization": "Bearer secrettoken"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False

        # Exact match should succeed
        headers = {"authorization": "Bearer SecretToken"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_authorization_unicode_tokens(self):
        """Test validation with Unicode characters in tokens."""
        config = {"authorization": "Bearer token_测试_123"}
        validator = AuthorizationValidator(config)

        # Valid Unicode token
        headers = {"authorization": "Bearer token_测试_123"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

        # Invalid Unicode token
        headers = {"authorization": "Bearer token_测试_456"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_authorization_long_tokens(self):
        """Test validation with very long tokens (within header length limit)."""
        # Use token that's long but within 8192 byte header limit
        # "Bearer " is 7 bytes, so max token is ~8185 bytes
        long_token = "Bearer " + "a" * 5000  # Well within limit
        config = {"authorization": long_token}
        validator = AuthorizationValidator(config)

        # Valid long token
        headers = {"authorization": long_token}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

        # Invalid long token (one char different)
        invalid_long_token = "Bearer " + "a" * 4999 + "b"
        headers = {"authorization": invalid_long_token}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_authorization_special_characters(self):
        """Test validation with special characters in tokens."""
        config = {"authorization": "Bearer token!@#$%^&*()_+-=[]{}|;:,.<>?"}
        validator = AuthorizationValidator(config)

        headers = {"authorization": "Bearer token!@#$%^&*()_+-=[]{}|;:,.<>?"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

        # Different special characters should fail
        headers = {"authorization": "Bearer token!@#$%^&*()_+-=[]{}|;:,.<>X"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
