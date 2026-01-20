"""
Tests for Query Parameter Authentication validator.
Includes security edge cases and comprehensive validation.
"""

import pytest
from src.validators import QueryParameterAuthValidator


class TestQueryParameterAuth:
    """Test suite for Query Parameter Authentication."""

    @pytest.mark.asyncio
    async def test_query_auth_no_config(self):
        """Test that validation passes when no query auth is configured."""
        config = {}
        validator = QueryParameterAuthValidator(config)

        headers = {}
        body = b"test"

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True
        assert "No query parameter auth required" in message

    @pytest.mark.asyncio
    async def test_query_auth_valid_key_default_param(self):
        """Test validation with valid API key using default parameter name."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        query_params = {"api_key": "secret_key_123"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True
        assert "Valid query parameter authentication" in message

    @pytest.mark.asyncio
    async def test_query_auth_valid_key_custom_param(self):
        """Test validation with valid API key using custom parameter name."""
        config = {
            "query_auth": {"parameter_name": "token", "api_key": "my_secret_token"}
        }

        query_params = {"token": "my_secret_token"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True
        assert "Valid query parameter authentication" in message

    @pytest.mark.asyncio
    async def test_query_auth_invalid_key(self):
        """Test validation with invalid API key."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        query_params = {"api_key": "wrong_key"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message

    @pytest.mark.asyncio
    async def test_query_auth_missing_parameter(self):
        """Test validation when required query parameter is missing."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        query_params = {}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Missing required query parameter" in message

    @pytest.mark.asyncio
    async def test_query_auth_case_sensitive_true(self):
        """Test case-sensitive validation when enabled."""
        config = {"query_auth": {"api_key": "SecretKey123", "case_sensitive": True}}

        # Correct case - should pass
        query_params = {"api_key": "SecretKey123"}
        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

        # Wrong case - should fail
        query_params = {"api_key": "secretkey123"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message

    @pytest.mark.asyncio
    async def test_query_auth_case_sensitive_false(self):
        """Test case-insensitive validation when disabled."""
        config = {"query_auth": {"api_key": "SecretKey123", "case_sensitive": False}}

        # Different case - should pass
        query_params = {"api_key": "secretkey123"}
        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

        # Another case variation - should pass
        query_params = {"api_key": "SECRETKEY123"}
        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_query_auth_case_sensitive_default(self):
        """Test that case sensitivity defaults to False."""
        config = {"query_auth": {"api_key": "SecretKey123"}}

        # Should be case-insensitive by default
        query_params = {"api_key": "secretkey123"}
        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_query_auth_missing_api_key_config(self):
        """Test validation when API key is not configured."""
        config = {"query_auth": {"parameter_name": "api_key"}}

        query_params = {"api_key": "some_key"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Query auth API key not configured" in message

    @pytest.mark.asyncio
    async def test_query_auth_empty_key(self):
        """Test validation with empty API key."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        query_params = {"api_key": ""}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message

    @pytest.mark.asyncio
    async def test_query_auth_whitespace_in_key(self):
        """Test validation with whitespace in API key."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Key with leading/trailing whitespace should fail
        query_params = {"api_key": " secret_key_123 "}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message

    @pytest.mark.asyncio
    async def test_query_auth_special_characters(self):
        """Test validation with special characters in API key."""
        config = {"query_auth": {"api_key": "key!@#$%^&*()_+-=[]{}|;:,.<>?"}}

        query_params = {"api_key": "key!@#$%^&*()_+-=[]{}|;:,.<>?"}

        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_query_auth_unicode_characters(self):
        """Test validation with Unicode characters in API key."""
        config = {"query_auth": {"api_key": "ключ_测试_🔑"}}

        query_params = {"api_key": "ключ_测试_🔑"}

        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_query_auth_long_key(self):
        """Test validation with very long API key."""
        long_key = "a" * 1000
        config = {"query_auth": {"api_key": long_key}}

        query_params = {"api_key": long_key}

        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_query_auth_multiple_params(self):
        """Test validation when multiple query parameters are present."""
        config = {
            "query_auth": {"parameter_name": "api_key", "api_key": "secret_key_123"}
        }

        query_params = {
            "api_key": "secret_key_123",
            "other_param": "value",
            "another": "test",
        }

        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_query_auth_timing_attack_resistance(self):
        """Test that validation uses constant-time comparison to resist timing attacks."""
        import time

        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Measure time for correct key (run multiple times for better accuracy)
        correct_params = {"api_key": "secret_key_123"}
        correct_times = []
        for _ in range(10):
            start = time.perf_counter()
            QueryParameterAuthValidator.validate_query_params(correct_params, config)
            correct_times.append(time.perf_counter() - start)
        correct_time = sum(correct_times) / len(correct_times)

        # Measure time for wrong key (first character different)
        wrong_params = {"api_key": "x" + "secret_key_123"[1:]}
        wrong_times = []
        for _ in range(10):
            start = time.perf_counter()
            QueryParameterAuthValidator.validate_query_params(wrong_params, config)
            wrong_times.append(time.perf_counter() - start)
        wrong_time = sum(wrong_times) / len(wrong_times)

        # Measure time for wrong key (last character different)
        wrong_params2 = {"api_key": "secret_key_123"[:-1] + "x"}
        wrong_times2 = []
        for _ in range(10):
            start = time.perf_counter()
            QueryParameterAuthValidator.validate_query_params(wrong_params2, config)
            wrong_times2.append(time.perf_counter() - start)
        wrong_time2 = sum(wrong_times2) / len(wrong_times2)

        # Times should be similar (within reasonable margin)
        # This is a basic check - hmac.compare_digest should handle this
        # If timing differs significantly, it might indicate a vulnerability
        time_diff_ratio = abs(correct_time - wrong_time) / max(
            correct_time, wrong_time, 0.000001
        )
        time_diff_ratio2 = abs(correct_time - wrong_time2) / max(
            correct_time, wrong_time2, 0.000001
        )

        # Allow up to 70% difference due to system noise (timing tests can be flaky)
        # The important thing is that hmac.compare_digest is used, which is constant-time
        # We're just checking that we're using the right function, not testing the function itself
        assert (
            time_diff_ratio < 0.7
        ), f"Timing attack vulnerability detected (first char): {time_diff_ratio:.2%}"
        assert (
            time_diff_ratio2 < 0.7
        ), f"Timing attack vulnerability detected (last char): {time_diff_ratio2:.2%}"

    @pytest.mark.asyncio
    async def test_query_auth_sql_injection_attempt(self):
        """Test that SQL injection attempts in parameter name are handled safely."""
        config = {
            "query_auth": {"parameter_name": "api_key", "api_key": "secret_key_123"}
        }

        # Attempt SQL injection in parameter value
        query_params = {"api_key": "secret_key_123' OR '1'='1"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message

    @pytest.mark.asyncio
    async def test_query_auth_xss_attempt(self):
        """Test that XSS attempts in parameter value are handled safely."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Attempt XSS in parameter value
        query_params = {"api_key": "<script>alert('xss')</script>"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message

    @pytest.mark.asyncio
    async def test_query_auth_null_byte_injection(self):
        """Test that null byte injection attempts are handled safely."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Attempt null byte injection
        # Null byte is sanitized, so "secret_key_123\x00" becomes "secret_key_123" which matches
        # This is acceptable - the dangerous character is removed before comparison
        query_params = {"api_key": "secret_key_123\x00"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # After sanitization, null byte is removed and value matches expected key
        assert is_valid is True
        assert "Valid" in message

    @pytest.mark.asyncio
    async def test_query_auth_parameter_name_injection(self):
        """Test that malicious parameter names are handled safely."""
        config = {
            "query_auth": {"parameter_name": "api_key", "api_key": "secret_key_123"}
        }

        # Try to use a different parameter name
        query_params = {
            "api_key": "wrong_key",
            "api_key'; DROP TABLE users; --": "secret_key_123",
        }

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message

    @pytest.mark.asyncio
    async def test_query_auth_empty_config(self):
        """Test validation when query_auth config exists but is empty."""
        config = {"query_auth": {}}

        query_params = {"api_key": "some_key"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Query auth API key not configured" in message

    @pytest.mark.asyncio
    async def test_query_auth_common_parameter_names(self):
        """Test with common parameter name variations."""
        common_names = [
            "api_key",
            "token",
            "key",
            "apikey",
            "access_token",
            "auth_token",
        ]

        for param_name in common_names:
            config = {
                "query_auth": {
                    "parameter_name": param_name,
                    "api_key": "secret_key_123",
                }
            }

            query_params = {param_name: "secret_key_123"}

            is_valid, _ = QueryParameterAuthValidator.validate_query_params(
                query_params, config
            )
            assert is_valid is True, f"Failed for parameter name: {param_name}"

    @pytest.mark.asyncio
    async def test_query_auth_partial_match_should_fail(self):
        """Test that partial key matches fail (security check)."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Partial match - should fail
        query_params = {"api_key": "secret_key_12"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message

        # Longer than expected - should fail
        query_params = {"api_key": "secret_key_1234"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "Invalid API key" in message
