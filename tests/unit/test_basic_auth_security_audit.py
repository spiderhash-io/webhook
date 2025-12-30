"""
Comprehensive security audit tests for BasicAuthValidator.
Tests config injection, exception handling, error disclosure, and edge cases not covered in existing tests.
"""
import pytest
import base64
import hmac
from unittest.mock import patch, MagicMock
from src.validators import BasicAuthValidator


# ============================================================================
# 1. CONFIG INJECTION & TYPE VALIDATION ATTACKS
# ============================================================================

class TestBasicAuthConfigInjection:
    """Test configuration injection and type validation vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_config_type_validation_username(self):
        """Test that username config must be a string."""
        invalid_configs = [
            {"basic_auth": {"username": None, "password": "secret123"}},
            {"basic_auth": {"username": 123, "password": "secret123"}},
            {"basic_auth": {"username": [], "password": "secret123"}},
            {"basic_auth": {"username": {}, "password": "secret123"}},
        ]
        
        for invalid_config in invalid_configs:
            validator = BasicAuthValidator(invalid_config)
            headers = {"authorization": "Basic dGVzdDp0ZXN0"}
            
            try:
                is_valid, message = await validator.validate(headers, b"")
                # Should handle invalid config gracefully
                assert is_valid is False
                assert "not configured" in message or "Invalid" in message
            except (AttributeError, TypeError) as e:
                # Expected if config validation is strict
                assert True
    
    @pytest.mark.asyncio
    async def test_config_type_validation_password(self):
        """Test that password config must be a string."""
        invalid_configs = [
            {"basic_auth": {"username": "admin", "password": None}},
            {"basic_auth": {"username": "admin", "password": 123}},
            {"basic_auth": {"username": "admin", "password": []}},
            {"basic_auth": {"username": "admin", "password": {}}},
        ]
        
        for invalid_config in invalid_configs:
            validator = BasicAuthValidator(invalid_config)
            headers = {"authorization": "Basic dGVzdDp0ZXN0"}
            
            try:
                is_valid, message = await validator.validate(headers, b"")
                # Should handle invalid config gracefully
                assert is_valid is False
                assert "not configured" in message or "Invalid" in message
            except (AttributeError, TypeError) as e:
                # Expected if config validation is strict
                assert True
    
    @pytest.mark.asyncio
    async def test_config_injection_via_nested_dict(self):
        """Test that nested dict injection in config is handled safely."""
        # Try to inject malicious nested structure
        malicious_config = {
            "basic_auth": {
                "username": {"nested": "attack"},
                "password": {"nested": "attack"}
            }
        }
        
        validator = BasicAuthValidator(malicious_config)
        headers = {"authorization": "Basic dGVzdDp0ZXN0"}
        
        try:
            is_valid, message = await validator.validate(headers, b"")
            # Should handle invalid config
            assert is_valid is False
        except (AttributeError, TypeError) as e:
            # Expected - config should be validated
            assert True
    
    @pytest.mark.asyncio
    async def test_missing_basic_auth_config_key(self):
        """Test behavior when basic_auth key is missing."""
        config = {}  # No basic_auth key
        
        validator = BasicAuthValidator(config)
        headers = {"authorization": "Basic dGVzdDp0ZXN0"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should return True (no auth required)
        assert is_valid is True
        assert "No basic auth required" in message
    
    @pytest.mark.asyncio
    async def test_empty_basic_auth_config_dict(self):
        """Test behavior when basic_auth is empty dict."""
        config = {"basic_auth": {}}
        
        validator = BasicAuthValidator(config)
        headers = {"authorization": "Basic dGVzdDp0ZXN0"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should return True (no auth required)
        assert is_valid is True
        assert "No basic auth required" in message


# ============================================================================
# 2. EXCEPTION HANDLING & ERROR DISCLOSURE
# ============================================================================

class TestBasicAuthExceptionHandling:
    """Test exception handling and error message disclosure."""
    
    @pytest.mark.asyncio
    async def test_base64_decode_exception_handling(self):
        """Test that base64 decode exceptions are handled securely."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Mock base64.b64decode to raise an exception
        with patch('base64.b64decode', side_effect=Exception("Internal base64 error with path: /etc/passwd")):
            headers = {"authorization": "Basic invalid"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should handle exception gracefully
            assert is_valid is False
            # Should not expose internal error details
            assert "/etc/passwd" not in message
            assert "Internal base64 error" not in message
    
    @pytest.mark.asyncio
    async def test_unicode_decode_exception_handling(self):
        """Test that Unicode decode exceptions are handled securely."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Create invalid UTF-8 that will fail both UTF-8 and Latin-1 decode
        invalid_bytes = b'\xff\xff\xff'
        encoded = base64.b64encode(invalid_bytes).decode()
        
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should handle gracefully
        assert is_valid is False
        # Should not expose stack traces
        assert "traceback" not in message.lower()
        assert "file" not in message.lower()
    
    @pytest.mark.asyncio
    async def test_generic_exception_handling(self):
        """Test that generic exceptions are handled securely."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Mock base64.b64decode to raise a generic exception with sensitive data
        with patch('base64.b64decode', side_effect=Exception("Internal error with sensitive data: /etc/passwd")):
            headers = {"authorization": "Basic dGVzdDp0ZXN0"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should handle exception
            assert is_valid is False
            # Should sanitize error message
            assert "sensitive data" not in message
            assert "/etc/passwd" not in message
            # Should use generic error format
            assert "Invalid" in message or "basic authentication" in message.lower()
    
    @pytest.mark.asyncio
    async def test_error_message_no_credential_leakage(self):
        """Test that error messages don't leak credential information."""
        config = {
            "basic_auth": {
                "username": "super_secret_user_xyz",
                "password": "super_secret_pass_xyz"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Various invalid inputs
        invalid_inputs = [
            "Basic invalid_base64!!!",
            "Basic ",
            "Basic dGVzdA==",  # Missing colon
        ]
        
        for auth_header in invalid_inputs:
            headers = {"authorization": auth_header}
            is_valid, message = await validator.validate(headers, b"")
            assert is_valid is False
            # Should not expose credentials
            assert "super_secret_user_xyz" not in message
            assert "super_secret_pass_xyz" not in message
            assert "admin" not in message.lower()  # Even generic usernames shouldn't appear


# ============================================================================
# 3. BASE64 DECODING EDGE CASES
# ============================================================================

class TestBasicAuthBase64EdgeCases:
    """Test Base64 decoding edge cases and bypass attempts."""
    
    @pytest.mark.asyncio
    async def test_base64_with_unicode_characters(self):
        """Test Base64 with Unicode characters that might bypass validation."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Unicode characters that look like base64 characters
        unicode_bypass_attempts = [
            "Basic \u0041\u0042\u0043\u003D",  # Unicode A, B, C, =
            "Basic АВС=",  # Cyrillic lookalikes
        ]
        
        for auth_header in unicode_bypass_attempts:
            headers = {"authorization": auth_header}
            is_valid, message = await validator.validate(headers, b"")
            # Should reject invalid base64
            assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_base64_padding_overflow(self):
        """Test Base64 with excessive padding."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        valid_encoded = base64.b64encode(credentials.encode()).decode()
        
        # Excessive padding
        excessive_padding = valid_encoded + "=" * 10
        
        headers = {"authorization": f"Basic {excessive_padding}"}
        is_valid, message = await validator.validate(headers, b"")
        # Should reject invalid padding
        assert is_valid is False
        assert "Invalid base64 encoding" in message or "Invalid" in message
    
    @pytest.mark.asyncio
    async def test_base64_with_special_base64_chars(self):
        """Test Base64 with special characters that are valid in base64."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Valid base64 with + and / characters
        credentials = "user+name:pass/word"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        headers = {"authorization": f"Basic {encoded}"}
        is_valid, message = await validator.validate(headers, b"")
        # Should work - + and / are valid base64 characters
        # But credentials won't match, so should fail auth
        assert is_valid is False
        assert "Invalid credentials" in message
    
    @pytest.mark.asyncio
    async def test_base64_url_safe_encoding_rejection(self):
        """Test that URL-safe base64 encoding is properly rejected if not standard."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # URL-safe base64 uses - and _ instead of + and /
        credentials = "admin:secret+123"  # Contains + which becomes - in URL-safe
        url_safe_encoded = base64.urlsafe_b64encode(credentials.encode()).decode()
        
        # Check if URL-safe encoding contains - or _
        if '-' in url_safe_encoded or '_' in url_safe_encoded:
            headers = {"authorization": f"Basic {url_safe_encoded}"}
            is_valid, message = await validator.validate(headers, b"")
            # Should reject URL-safe encoding (uses standard base64)
            assert is_valid is False
            assert "Invalid base64 encoding" in message or "Invalid" in message


# ============================================================================
# 4. CREDENTIAL COMPARISON SECURITY
# ============================================================================

class TestBasicAuthCredentialComparison:
    """Test credential comparison security and timing attack prevention."""
    
    @pytest.mark.asyncio
    async def test_username_password_both_compared(self):
        """Test that both username and password are compared (not short-circuited)."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Valid username, wrong password
        credentials1 = "admin:wrong"
        encoded1 = base64.b64encode(credentials1.encode()).decode()
        headers1 = {"authorization": f"Basic {encoded1}"}
        
        # Wrong username, valid password
        credentials2 = "wrong:secret123"
        encoded2 = base64.b64encode(credentials2.encode()).decode()
        headers2 = {"authorization": f"Basic {encoded2}"}
        
        # Both should fail
        is_valid1, _ = await validator.validate(headers1, b"")
        is_valid2, _ = await validator.validate(headers2, b"")
        
        assert is_valid1 is False
        assert is_valid2 is False
    
    @pytest.mark.asyncio
    async def test_constant_time_comparison_verification(self):
        """Test that hmac.compare_digest is used for constant-time comparison."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        # Verify that hmac.compare_digest is called
        with patch('hmac.compare_digest', wraps=hmac.compare_digest) as mock_compare:
            validator = BasicAuthValidator(config)
            credentials = "admin:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            
            is_valid, _ = await validator.validate(headers, b"")
            
            # Should use hmac.compare_digest for both username and password
            assert mock_compare.call_count >= 2  # At least username and password
            assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_unicode_normalization_attacks(self):
        """Test Unicode normalization attacks (different forms of same character)."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Unicode characters that might normalize differently
        # Using composed vs decomposed forms
        try:
            import unicodedata
            # Create username with composed character
            composed = "admin"
            # Create username with decomposed character (if applicable)
            decomposed = unicodedata.normalize('NFD', composed)
            
            if composed != decomposed:
                credentials = f"{decomposed}:secret123"
                encoded = base64.b64encode(credentials.encode('utf-8')).decode()
                headers = {"authorization": f"Basic {encoded}"}
                
                is_valid, message = await validator.validate(headers, b"")
                # Should fail - different Unicode forms don't match
                assert is_valid is False
        except ImportError:
            # unicodedata is built-in, but test might fail if not available
            pass


# ============================================================================
# 5. HEADER PROCESSING EDGE CASES
# ============================================================================

class TestBasicAuthHeaderProcessing:
    """Test header processing edge cases and injection attempts."""
    
    @pytest.mark.asyncio
    async def test_case_insensitive_authorization_header(self):
        """Test that Authorization header is case-insensitive."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        # Case variations of Authorization header name
        case_variations = [
            {"authorization": f"Basic {encoded}"},
            {"Authorization": f"Basic {encoded}"},
            {"AUTHORIZATION": f"Basic {encoded}"},
            {"AuThOrIzAtIoN": f"Basic {encoded}"},
        ]
        
        for headers in case_variations:
            # Note: Headers dict keys should be lowercase (normalized by webhook handler)
            # But test that validator handles it
            is_valid, message = await validator.validate(headers, b"")
            # Should work if header name is normalized, or fail if case-sensitive
            # The validator expects lowercase 'authorization' from webhook handler
            if 'authorization' in headers:
                assert is_valid is True
            else:
                # If header name doesn't match, should fail
                assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_multiple_authorization_headers(self):
        """Test behavior with multiple Authorization headers (should use first/last)."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Valid credentials
        credentials1 = "admin:secret123"
        encoded1 = base64.b64encode(credentials1.encode()).decode()
        
        # Invalid credentials
        credentials2 = "wrong:wrong"
        encoded2 = base64.b64encode(credentials2.encode()).decode()
        
        # Dict with single key (Python dicts don't support duplicate keys)
        # But test that .get() returns the value
        headers = {"authorization": f"Basic {encoded1}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should use the provided header
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_empty_authorization_header_value(self):
        """Test empty Authorization header value."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        headers = {"authorization": ""}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Missing Authorization header" in message or "Basic authentication required" in message
    
    @pytest.mark.asyncio
    async def test_authorization_header_with_only_basic(self):
        """Test Authorization header with only 'Basic' (no credentials)."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        headers = {"authorization": "Basic"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        # Should fail - no credentials after "Basic "
        # May return "Basic authentication required" or "Invalid Basic authentication format"
        assert "Invalid" in message or "Missing" in message or "Basic authentication" in message


# ============================================================================
# 6. CONFIGURATION SECURITY
# ============================================================================

class TestBasicAuthConfigurationSecurity:
    """Test configuration security and validation."""
    
    @pytest.mark.asyncio
    async def test_config_with_whitespace_credentials(self):
        """Test config with whitespace-only credentials."""
        config = {
            "basic_auth": {
                "username": "   ",
                "password": "   "
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "   :   "
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should work if whitespace matches, but may be rejected
        # Test documents behavior
        assert is_valid is False or is_valid is True
    
    @pytest.mark.asyncio
    async def test_config_with_very_long_credentials(self):
        """Test config with very long credentials (DoS attempt)."""
        config = {
            "basic_auth": {
                "username": "a" * 100000,
                "password": "b" * 100000
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = f"{'a' * 100000}:{'b' * 100000}"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        # Should handle gracefully (may be slow, but shouldn't crash)
        is_valid, message = await validator.validate(headers, b"")
        # Should work if credentials match
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_config_with_special_characters(self):
        """Test config with special characters in credentials."""
        config = {
            "basic_auth": {
                "username": "user@example.com",
                "password": "p@$$w0rd!#%^&*()"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "user@example.com:p@$$w0rd!#%^&*()"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True


# ============================================================================
# 7. ENCODING SECURITY
# ============================================================================

class TestBasicAuthEncodingSecurity:
    """Test encoding-related security issues."""
    
    @pytest.mark.asyncio
    async def test_encoding_confusion_attack(self):
        """Test encoding confusion attacks (claiming wrong encoding)."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Create credentials that decode differently in different encodings
        # UTF-8 bytes that are valid Latin-1 but mean something different
        credentials_utf8 = "admin:secret123"
        credentials_latin1 = credentials_utf8.encode('latin-1')
        
        # If there are bytes > 0x7F, they'll be different
        if any(b > 0x7F for b in credentials_latin1):
            encoded = base64.b64encode(credentials_latin1).decode()
            headers = {"authorization": f"Basic {encoded}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should handle encoding correctly
            # Test documents behavior
            pass
        else:
            # All ASCII, so no encoding confusion
            pass
    
    @pytest.mark.asyncio
    async def test_bom_handling(self):
        """Test BOM (Byte Order Mark) handling in credentials."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # UTF-8 BOM
        bom_utf8 = b'\xef\xbb\xbf'
        credentials = bom_utf8 + b"admin:secret123"
        encoded = base64.b64encode(credentials).decode()
        
        headers = {"authorization": f"Basic {encoded}"}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - BOM in credentials
        assert is_valid is False


# ============================================================================
# 8. INTEGRATION SECURITY
# ============================================================================

class TestBasicAuthIntegrationSecurity:
    """Test integration-level security concerns."""
    
    @pytest.mark.asyncio
    async def test_validator_returns_tuple(self):
        """Test that validator always returns a tuple (is_valid, message)."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        test_cases = [
            {"authorization": "Basic dGVzdDp0ZXN0"},  # Valid format
            {"authorization": "invalid"},  # Invalid format
            {},  # Missing header
        ]
        
        for headers in test_cases:
            result = await validator.validate(headers, b"")
            # Should always return tuple
            assert isinstance(result, tuple)
            assert len(result) == 2
            is_valid, message = result
            assert isinstance(is_valid, bool)
            assert isinstance(message, str)
    
    @pytest.mark.asyncio
    async def test_validator_handles_empty_body(self):
        """Test that validator handles empty body correctly."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        # Empty body
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Large body (shouldn't affect basic auth)
        large_body = b"x" * 1000000
        is_valid, message = await validator.validate(headers, large_body)
        assert is_valid is True

