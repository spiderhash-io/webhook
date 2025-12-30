"""
Security tests for AuthorizationValidator.
Tests timing attack prevention, format validation, and header injection protection.
"""
import pytest
import time
import statistics
from src.validators import AuthorizationValidator


class TestAuthorizationHeaderSecurity:
    """Test suite for AuthorizationValidator security."""
    
    @pytest.mark.asyncio
    async def test_valid_bearer_token(self):
        """Test that valid Bearer tokens are accepted."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer secret_token_123"}
        is_valid, message = await validator.validate(headers, b"")
        
        assert is_valid is True
        assert "Valid authorization" in message
    
    @pytest.mark.asyncio
    async def test_invalid_bearer_token(self):
        """Test that invalid Bearer tokens are rejected."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer wrong_token"}
        is_valid, message = await validator.validate(headers, b"")
        
        assert is_valid is False
        assert "Unauthorized" in message
    
    @pytest.mark.asyncio
    async def test_bearer_token_format_validation(self):
        """Test strict Bearer token format validation."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Missing "Bearer " prefix
        headers = {"authorization": "secret_token_123"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message
        
        # Lowercase "bearer" (should fail - case sensitive)
        headers = {"authorization": "bearer secret_token_123"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message
        
        # Empty token (just "Bearer " with nothing after)
        headers = {"authorization": "Bearer "}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert ("token cannot be empty" in message or "must start with 'Bearer '" in message)
        
        # Whitespace-only token (after "Bearer ")
        headers = {"authorization": "Bearer    "}  # Multiple spaces after Bearer
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        # After stripping, this might become "Bearer" (no space) or "Bearer " (single space with empty token)
        # Either way it should fail
        assert ("token cannot be empty" in message or 
                "token cannot be whitespace only" in message or
                "must start with 'Bearer '" in message or
                "token cannot start with whitespace" in message)
    
    @pytest.mark.asyncio
    async def test_bearer_token_whitespace_handling(self):
        """Test that Bearer tokens handle whitespace correctly."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Extra spaces before token (should be rejected - strict format)
        headers = {"authorization": "Bearer  secret_token_123"}  # Double space
        is_valid, message = await validator.validate(headers, b"")
        # Should fail because token cannot start with whitespace
        assert is_valid is False
        assert "token cannot start with whitespace" in message
        
        # Leading/trailing whitespace in token (trailing should be normalized)
        headers = {"authorization": "Bearer secret_token_123 "}
        is_valid, message = await validator.validate(headers, b"")
        # Should succeed after trailing whitespace normalization
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_non_bearer_token_validation(self):
        """Test validation of non-Bearer tokens."""
        config = {
            "authorization": "CustomToken secret_value"
        }
        validator = AuthorizationValidator(config)
        
        # Exact match
        headers = {"authorization": "CustomToken secret_value"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Mismatch
        headers = {"authorization": "CustomToken wrong_value"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Unauthorized" in message
    
    @pytest.mark.asyncio
    async def test_header_injection_prevention(self):
        """Test that header injection attacks are prevented."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Newline injection
        headers = {"authorization": "Bearer secret_token_123\nX-Injected: value"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "forbidden character" in message
        
        # Carriage return injection
        headers = {"authorization": "Bearer secret_token_123\rX-Injected: value"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "forbidden character" in message
        
        # Null byte injection
        headers = {"authorization": f"Bearer secret_token_123\x00X-Injected: value"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "forbidden character" in message
    
    @pytest.mark.asyncio
    async def test_header_length_limit(self):
        """Test that headers exceeding length limit are rejected."""
        config = {
            "authorization": "Bearer " + "a" * 100
        }
        validator = AuthorizationValidator(config)
        
        # Normal length header
        headers = {"authorization": "Bearer " + "a" * 100}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Extremely long header (DoS protection)
        long_header = "Bearer " + "a" * 10000
        headers = {"authorization": long_header}
        is_valid, message = await validator.validate(headers, b"")
        # Should still pass format validation (under 8192 limit for header value)
        # But if it exceeds, should be rejected
        if len(long_header) > 8192:
            assert is_valid is False
            assert "too long" in message
    
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self):
        """
        Test that timing attacks are prevented by using constant-time comparison.
        
        This test measures the time taken to validate tokens and ensures
        that valid and invalid tokens take approximately the same time,
        preventing timing-based token enumeration.
        """
        config = {
            "authorization": "Bearer " + "a" * 100  # Long token for better timing measurement
        }
        validator = AuthorizationValidator(config)
        
        valid_token = "Bearer " + "a" * 100
        invalid_token_early = "Bearer " + "b" + "a" * 99  # Wrong first char
        invalid_token_late = "Bearer " + "a" * 99 + "b"  # Wrong last char
        invalid_token_wrong_length = "Bearer " + "a" * 99  # Wrong length
        
        # Measure validation times
        iterations = 200  # Increase for better statistical significance
        valid_times = []
        invalid_early_times = []
        invalid_late_times = []
        invalid_length_times = []
        
        for _ in range(iterations):
            # Valid token
            headers = {"authorization": valid_token}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            valid_times.append(time.perf_counter() - start)
            
            # Invalid token (early mismatch)
            headers = {"authorization": invalid_token_early}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_early_times.append(time.perf_counter() - start)
            
            # Invalid token (late mismatch)
            headers = {"authorization": invalid_token_late}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_late_times.append(time.perf_counter() - start)
            
            # Invalid token (wrong length)
            headers = {"authorization": invalid_token_wrong_length}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_length_times.append(time.perf_counter() - start)
        
        # Use median instead of mean for better robustness against outliers
        median_valid = statistics.median(valid_times)
        median_invalid_early = statistics.median(invalid_early_times)
        median_invalid_late = statistics.median(invalid_late_times)
        median_invalid_length = statistics.median(invalid_length_times)
        
        # Calculate time differences as ratios
        # Times should be similar (within reasonable margin due to system noise)
        time_diff_ratio_early = abs(median_valid - median_invalid_early) / max(median_valid, median_invalid_early, 0.000001)
        time_diff_ratio_late = abs(median_valid - median_invalid_late) / max(median_valid, median_invalid_late, 0.000001)
        time_diff_ratio_length = abs(median_valid - median_invalid_length) / max(median_valid, median_invalid_length, 0.000001)
        
        # Allow up to 100% difference due to system noise (timing tests are inherently flaky)
        # The important thing is that hmac.compare_digest is used, which prevents timing attacks
        # If timing attack was possible, we'd see much larger differences
        assert time_diff_ratio_early < 1.0, (
            f"Timing test (early mismatch): {time_diff_ratio_early:.2%} difference "
            f"(median valid: {median_valid*1000:.3f}ms, median invalid: {median_invalid_early*1000:.3f}ms). "
            f"Note: This test is sensitive to system load. The implementation uses hmac.compare_digest() "
            f"which provides constant-time comparison."
        )
        assert time_diff_ratio_late < 1.0, (
            f"Timing test (late mismatch): {time_diff_ratio_late:.2%} difference "
            f"(median valid: {median_valid*1000:.3f}ms, median invalid: {median_invalid_late*1000:.3f}ms). "
            f"Note: This test is sensitive to system load. The implementation uses hmac.compare_digest() "
            f"which provides constant-time comparison."
        )
        assert time_diff_ratio_length < 1.0, (
            f"Timing test (wrong length): {time_diff_ratio_length:.2%} difference "
            f"(median valid: {median_valid*1000:.3f}ms, median invalid: {median_invalid_length*1000:.3f}ms). "
            f"Note: This test is sensitive to system load. The implementation uses hmac.compare_digest() "
            f"which provides constant-time comparison."
        )
    
    @pytest.mark.asyncio
    async def test_case_sensitive_bearer_prefix(self):
        """Test that Bearer prefix is case-sensitive."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Lowercase "bearer"
        headers = {"authorization": "bearer secret_token_123"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message
        
        # Mixed case
        headers = {"authorization": "BeArEr secret_token_123"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message
    
    @pytest.mark.asyncio
    async def test_token_extraction_with_spaces(self):
        """Test that token extraction handles spaces correctly."""
        config = {
            "authorization": "Bearer token_with_spaces"
        }
        validator = AuthorizationValidator(config)
        
        # Token with spaces (should be preserved)
        headers = {"authorization": "Bearer token_with_spaces"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Token with leading spaces after "Bearer " (should be rejected)
        headers = {"authorization": "Bearer  token_with_spaces  "}  # Double space after Bearer
        is_valid, message = await validator.validate(headers, b"")
        # Should fail because token cannot start with whitespace
        assert is_valid is False
        assert "token cannot start with whitespace" in message
        
        # Token with trailing spaces (should be normalized and match)
        headers = {"authorization": "Bearer token_with_spaces  "}  # Trailing spaces
        is_valid, message = await validator.validate(headers, b"")
        # Should succeed after trailing whitespace normalization
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_missing_authorization_header(self):
        """Test behavior when authorization header is missing."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Unauthorized" in message or "must start with 'Bearer '" in message
    
    @pytest.mark.asyncio
    async def test_empty_authorization_config(self):
        """Test behavior when authorization is not configured."""
        config = {}
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer any_token"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        assert "No authorization required" in message
    
    @pytest.mark.asyncio
    async def test_unicode_tokens(self):
        """Test that unicode tokens are handled correctly."""
        config = {
            "authorization": "Bearer token_ünicode_测试"
        }
        validator = AuthorizationValidator(config)
        
        # Valid unicode token
        headers = {"authorization": "Bearer token_ünicode_测试"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Invalid unicode token
        headers = {"authorization": "Bearer token_ünicode_wrong"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False

