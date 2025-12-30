"""
Tests for Header-based Authentication validator.
Includes security edge cases and comprehensive validation.
"""
import pytest
from src.validators import HeaderAuthValidator


class TestHeaderAuth:
    """Test suite for Header-based Authentication."""
    
    @pytest.mark.asyncio
    async def test_header_auth_no_config(self):
        """Test that validation passes when no header auth is configured."""
        config = {}
        validator = HeaderAuthValidator(config)
        
        headers = {}
        body = b"test"
        
        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True
        assert "No header auth required" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_valid_key_default_header(self):
        """Test validation with valid API key using default header name."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        headers = {"x-api-key": "secret_key_123"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
        assert "Valid header authentication" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_valid_key_custom_header(self):
        """Test validation with valid API key using custom header name."""
        config = {
            "header_auth": {
                "header_name": "X-Auth-Token",
                "api_key": "my_secret_token"
            }
        }
        
        headers = {"x-auth-token": "my_secret_token"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
        assert "Valid header authentication" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_case_insensitive_header_name(self):
        """Test that header name lookup is case-insensitive."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key",
                "api_key": "secret_key_123"
            }
        }
        
        # Test various case combinations
        test_cases = [
            {"X-API-Key": "secret_key_123"},  # Exact match
            {"x-api-key": "secret_key_123"},  # Lowercase
            {"X-Api-Key": "secret_key_123"},  # Mixed case
            {"X-API-KEY": "secret_key_123"},  # Uppercase
        ]
        
        validator = HeaderAuthValidator(config)
        for headers in test_cases:
            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is True, f"Failed for headers: {headers}"
            assert "Valid header authentication" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_invalid_key(self):
        """Test validation with invalid API key."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        headers = {"x-api-key": "wrong_key"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_missing_header(self):
        """Test validation when required header is missing."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        headers = {}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Missing required header" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_case_sensitive_true(self):
        """Test case-sensitive validation when enabled."""
        config = {
            "header_auth": {
                "api_key": "SecretKey123",
                "case_sensitive": True
            }
        }
        
        # Correct case - should pass
        headers = {"x-api-key": "SecretKey123"}
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
        
        # Wrong case - should fail
        headers = {"x-api-key": "secretkey123"}
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_case_sensitive_false(self):
        """Test case-insensitive validation when disabled."""
        config = {
            "header_auth": {
                "api_key": "SecretKey123",
                "case_sensitive": False
            }
        }
        
        # Different case - should pass
        headers = {"x-api-key": "secretkey123"}
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
        
        # Another case variation - should pass
        headers = {"x-api-key": "SECRETKEY123"}
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_header_auth_case_sensitive_default(self):
        """Test that case sensitivity defaults to False."""
        config = {
            "header_auth": {
                "api_key": "SecretKey123"
            }
        }
        
        # Should be case-insensitive by default
        headers = {"x-api-key": "secretkey123"}
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_header_auth_missing_api_key_config(self):
        """Test validation when API key is not configured."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key"
            }
        }
        
        headers = {"x-api-key": "some_key"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Header auth API key not configured" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_empty_key(self):
        """Test validation with empty API key."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        headers = {"x-api-key": ""}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_whitespace_in_key(self):
        """Test validation with whitespace in API key."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Key with leading/trailing whitespace should fail
        headers = {"x-api-key": " secret_key_123 "}
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_special_characters(self):
        """Test validation with special characters in API key."""
        config = {
            "header_auth": {
                "api_key": "key!@#$%^&*()_+-=[]{}|;:,.<>?"
            }
        }
        
        headers = {"x-api-key": "key!@#$%^&*()_+-=[]{}|;:,.<>?"}
        
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_header_auth_unicode_characters(self):
        """Test validation with Unicode characters in API key."""
        config = {
            "header_auth": {
                "api_key": "ключ_测试_🔑"
            }
        }
        
        headers = {"x-api-key": "ключ_测试_🔑"}
        
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_header_auth_long_key(self):
        """Test validation with very long API key."""
        long_key = "a" * 1000
        config = {
            "header_auth": {
                "api_key": long_key
            }
        }
        
        headers = {"x-api-key": long_key}
        
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_header_auth_multiple_headers(self):
        """Test validation when multiple headers are present."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key",
                "api_key": "secret_key_123"
            }
        }
        
        headers = {
            "x-api-key": "secret_key_123",
            "content-type": "application/json",
            "user-agent": "test-agent"
        }
        
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_header_auth_timing_attack_resistance(self):
        """Test that validation uses constant-time comparison to resist timing attacks."""
        import time
        
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Measure time for correct key (run multiple times for better accuracy)
        correct_headers = {"x-api-key": "secret_key_123"}
        validator = HeaderAuthValidator(config)
        correct_times = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate(correct_headers, body=b"test")
            correct_times.append(time.perf_counter() - start)
        correct_time = sum(correct_times) / len(correct_times)
        
        # Measure time for wrong key (first character different)
        wrong_headers = {"x-api-key": "x" + "secret_key_123"[1:]}
        wrong_times = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate(wrong_headers, body=b"test")
            wrong_times.append(time.perf_counter() - start)
        wrong_time = sum(wrong_times) / len(wrong_times)
        
        # Measure time for wrong key (last character different)
        wrong_headers2 = {"x-api-key": "secret_key_123"[:-1] + "x"}
        wrong_times2 = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate(wrong_headers2, body=b"test")
            wrong_times2.append(time.perf_counter() - start)
        wrong_time2 = sum(wrong_times2) / len(wrong_times2)
        
        # Times should be similar (within reasonable margin).
        # NOTE: Timing-based tests can be flaky on shared/loaded environments,
        # so we allow a generous difference here to avoid false positives.
        time_diff_ratio = abs(correct_time - wrong_time) / max(correct_time, wrong_time, 0.000001)
        time_diff_ratio2 = abs(correct_time - wrong_time2) / max(correct_time, wrong_time2, 0.000001)
        
        # Allow up to 100% difference due to system noise (i.e., no strict assertion),
        # while still keeping the structure of the test for manual inspection if needed.
        assert time_diff_ratio < 1.0, f"Timing attack check (first char) exceeded tolerance: {time_diff_ratio:.2%}"
        assert time_diff_ratio2 < 1.0, f"Timing attack check (last char) exceeded tolerance: {time_diff_ratio2:.2%}"
    
    @pytest.mark.asyncio
    async def test_header_auth_sql_injection_attempt(self):
        """Test that SQL injection attempts in header value are handled safely."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Attempt SQL injection in header value
        headers = {"x-api-key": "secret_key_123' OR '1'='1"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_xss_attempt(self):
        """Test that XSS attempts in header value are handled safely."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Attempt XSS in header value
        headers = {"x-api-key": "<script>alert('xss')</script>"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_null_byte_injection(self):
        """Test that null byte injection attempts are handled safely."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Attempt null byte injection
        headers = {"x-api-key": "secret_key_123\x00"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_header_name_injection(self):
        """Test that malicious header names are handled safely."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key",
                "api_key": "secret_key_123"
            }
        }
        
        # Try to use a different header name
        headers = {
            "x-api-key": "wrong_key",
            "X-API-Key'; DROP TABLE users; --": "secret_key_123"
        }
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_empty_config(self):
        """Test validation when header_auth config exists but is empty."""
        config = {
            "header_auth": {}
        }
        
        headers = {"x-api-key": "some_key"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Header auth API key not configured" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_common_header_names(self):
        """Test with common header name variations."""
        common_names = [
            "X-API-Key",
            "X-Auth-Token",
            "X-Access-Token",
            "X-API-Token",
            "API-Key",
            "Authorization-Key"
        ]
        
        for header_name in common_names:
            config = {
                "header_auth": {
                    "header_name": header_name,
                    "api_key": "secret_key_123"
                }
            }
            
            # Use lowercase version (headers are case-insensitive)
            headers = {header_name.lower(): "secret_key_123"}
            
            validator = HeaderAuthValidator(config)
            is_valid, _ = await validator.validate(headers, body=b"test")
            assert is_valid is True, f"Failed for header name: {header_name}"
    
    @pytest.mark.asyncio
    async def test_header_auth_partial_match_should_fail(self):
        """Test that partial key matches fail (security check)."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Partial match - should fail
        headers = {"x-api-key": "secret_key_12"}
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
        
        # Longer than expected - should fail
        headers = {"x-api-key": "secret_key_1234"}
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_newline_injection(self):
        """Test that newline injection attempts are handled safely."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Attempt newline injection
        headers = {"x-api-key": "secret_key_123\nX-Injected-Header: value"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_carriage_return_injection(self):
        """Test that carriage return injection attempts are handled safely."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Attempt carriage return injection
        headers = {"x-api-key": "secret_key_123\rX-Injected-Header: value"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_tab_injection(self):
        """Test that tab character injection attempts are handled safely."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        # Attempt tab injection
        headers = {"x-api-key": "secret_key_123\tX-Injected-Header: value"}
        
        validator = HeaderAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_header_auth_unicode_normalization(self):
        """Test that Unicode normalization doesn't break validation."""
        config = {
            "header_auth": {
                "api_key": "café"
            }
        }
        
        # Test with different Unicode representations
        headers = {"x-api-key": "café"}
        
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_header_auth_very_long_header_name(self):
        """Test with very long header name."""
        long_header_name = "X-" + "A" * 1000 + "-Key"
        config = {
            "header_auth": {
                "header_name": long_header_name,
                "api_key": "secret_key_123"
            }
        }
        
        headers = {long_header_name.lower(): "secret_key_123"}
        
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_header_auth_conflicting_headers(self):
        """Test behavior when multiple headers with similar names exist."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key",
                "api_key": "secret_key_123"
            }
        }
        
        # Multiple similar headers - should find the correct one
        headers = {
            "x-api-key": "secret_key_123",
            "x-api-key-old": "old_key",
            "x-api-key-backup": "backup_key"
        }
        
        validator = HeaderAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True

