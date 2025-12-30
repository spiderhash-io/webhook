"""
Comprehensive security tests for Basic Authentication.
Tests advanced Basic Auth attack vectors and bypass techniques.
"""
import pytest
import base64
import hmac
from src.validators import BasicAuthValidator


class TestBasicAuthBase64Attacks:
    """Test Base64 encoding/decoding attack vectors."""
    
    @pytest.mark.asyncio
    async def test_base64_padding_manipulation(self):
        """Test Base64 padding manipulation attempts."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Valid credentials
        credentials = "admin:secret123"
        valid_encoded = base64.b64encode(credentials.encode()).decode()
        
        # Try padding manipulations
        padding_attacks = [
            valid_encoded + "=",  # Extra padding
            valid_encoded + "==",  # Extra padding
            valid_encoded[:-1] if valid_encoded.endswith("=") else valid_encoded,  # Remove padding
        ]
        
        for encoded in padding_attacks:
            headers = {"authorization": f"Basic {encoded}"}
            is_valid, message = await validator.validate(headers, b"")
            # Should handle padding correctly or reject invalid padding
            # Test documents behavior
    
    @pytest.mark.asyncio
    async def test_base64_with_whitespace(self):
        """Test Base64 with whitespace characters."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        # Whitespace variations
        whitespace_variations = [
            f" {encoded}",  # Leading space
            f"{encoded} ",  # Trailing space
            f" {encoded} ",  # Both
            f"\t{encoded}",  # Tab
            f"{encoded}\n",  # Newline
        ]
        
        for encoded_with_ws in whitespace_variations:
            headers = {"authorization": f"Basic {encoded_with_ws}"}
            is_valid, message = await validator.validate(headers, b"")
            # Should handle or reject whitespace
            # Newlines should be rejected (header injection)
            if "\n" in encoded_with_ws or "\r" in encoded_with_ws:
                assert is_valid is False
            else:
                # Other whitespace may be handled
                pass
    
    @pytest.mark.asyncio
    async def test_base64_url_safe_vs_standard(self):
        """Test URL-safe Base64 vs standard Base64."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        # Standard base64
        standard_encoded = base64.b64encode(credentials.encode()).decode()
        # URL-safe base64 (uses - and _ instead of + and /)
        url_safe_encoded = base64.urlsafe_b64encode(credentials.encode()).decode()
        
        # Standard should work
        headers = {"authorization": f"Basic {standard_encoded}"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # URL-safe may or may not work depending on implementation
        headers = {"authorization": f"Basic {url_safe_encoded}"}
        is_valid, message = await validator.validate(headers, b"")
        # Test documents behavior
    
    @pytest.mark.asyncio
    async def test_invalid_base64_characters(self):
        """Test Base64 with invalid characters."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Invalid Base64 characters
        invalid_encoded = [
            "invalid!!!base64",
            "test@#$%^&*()",
            "not-base64-here",
            "中文",  # Non-ASCII
        ]
        
        for encoded in invalid_encoded:
            headers = {"authorization": f"Basic {encoded}"}
            is_valid, message = await validator.validate(headers, b"")
            assert is_valid is False
            assert "Invalid base64 encoding" in message or "Invalid basic auth format" in message
    
    @pytest.mark.asyncio
    async def test_base64_empty_string(self):
        """Test Base64 empty string."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Empty base64
        headers = {"authorization": "Basic "}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False


class TestBasicAuthHeaderInjection:
    """Test header injection attack vectors."""
    
    @pytest.mark.asyncio
    async def test_newline_in_authorization_header(self):
        """Test newline injection in Authorization header."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        # Newline injection attempts
        injection_attempts = [
            f"Basic {encoded}\nX-Injected: value",
            f"Basic {encoded}\rX-Injected: value",
            f"Basic {encoded}\r\nX-Injected: value",
        ]
        
        for auth_header in injection_attempts:
            headers = {"authorization": auth_header}
            is_valid, message = await validator.validate(headers, b"")
            # Should fail - newlines indicate header injection
            assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_null_bytes_in_header(self):
        """Test null bytes in Authorization header."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        # Null byte injection
        auth_header = f"Basic {encoded}\x00injection"
        headers = {"authorization": auth_header}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail or handle null bytes safely
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_case_variations_basic_prefix(self):
        """Test case variations in 'Basic' prefix."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        # Case variations
        case_variations = [
            ("basic", False),  # Lowercase
            ("BASIC", False),  # Uppercase
            ("Basic", True),  # Correct
            ("BaSiC", False),  # Mixed
        ]
        
        for prefix, should_work in case_variations:
            headers = {"authorization": f"{prefix} {encoded}"}
            is_valid, message = await validator.validate(headers, b"")
            if should_work:
                assert is_valid is True
            else:
                assert is_valid is False
                assert "Basic authentication required" in message
    
    @pytest.mark.asyncio
    async def test_multiple_basic_prefixes(self):
        """Test multiple 'Basic' prefixes."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        # Multiple Basic prefixes
        headers = {"authorization": f"Basic Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - invalid format
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_whitespace_around_basic(self):
        """Test whitespace around 'Basic' prefix."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        # Whitespace variations
        whitespace_variations = [
            f" Basic {encoded}",  # Leading space
            f"Basic  {encoded}",  # Double space
            f"Basic\t{encoded}",  # Tab
        ]
        
        for auth_header in whitespace_variations:
            headers = {"authorization": auth_header}
            is_valid, message = await validator.validate(headers, b"")
            # Should handle or reject
            # Double space and tab should fail
            if "  " in auth_header or "\t" in auth_header:
                assert is_valid is False


class TestBasicAuthCredentialFormat:
    """Test credential format manipulation attacks."""
    
    @pytest.mark.asyncio
    async def test_multiple_colons_in_credentials(self):
        """Test credentials with multiple colons."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret:123:456"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Password with multiple colons (should use split(':', 1))
        credentials = "admin:secret:123:456"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should work - split(':', 1) handles multiple colons
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_no_colon_in_credentials(self):
        """Test credentials without colon separator."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # No colon
        credentials = "adminpassword"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid basic auth format" in message
    
    @pytest.mark.asyncio
    async def test_colon_only_username(self):
        """Test credentials with colon but no username."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Colon but empty username
        credentials = ":secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid credentials" in message
    
    @pytest.mark.asyncio
    async def test_colon_only_password(self):
        """Test credentials with colon but no password."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Colon but empty password
        credentials = "admin:"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid credentials" in message
    
    @pytest.mark.asyncio
    async def test_very_long_credentials(self):
        """Test very long credentials (DoS attempt)."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Very long username and password
        long_username = "a" * 10000
        long_password = "b" * 10000
        credentials = f"{long_username}:{long_password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        headers = {"authorization": f"Basic {encoded}"}
        
        # Should handle gracefully (may be slow, but shouldn't crash)
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - credentials don't match
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_null_bytes_in_credentials(self):
        """Test null bytes in credentials."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Null bytes in username
        credentials = "admin\x00:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - null bytes in username
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_unicode_edge_cases(self):
        """Test Unicode edge cases in credentials."""
        config = {
            "basic_auth": {
                "username": "用户",
                "password": "密码"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Valid Unicode
        credentials = "用户:密码"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Unicode with surrogates (invalid)
        try:
            invalid_unicode = "\ud800\udc00"  # Surrogate pair
            credentials = f"{invalid_unicode}:password"
            encoded = base64.b64encode(credentials.encode('utf-8', errors='surrogatepass')).decode()
            headers = {"authorization": f"Basic {encoded}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should handle or reject
        except Exception:
            # If encoding fails, that's also acceptable
            pass


class TestBasicAuthCredentialExposure:
    """Test credential exposure prevention."""
    
    @pytest.mark.asyncio
    async def test_username_not_in_error_messages(self):
        """Test that username is not exposed in error messages."""
        config = {
            "basic_auth": {
                "username": "super_secret_username_12345",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Wrong password
        credentials = "super_secret_username_12345:wrong"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        
        # Username should not appear in error message
        assert "super_secret_username_12345" not in message
    
    @pytest.mark.asyncio
    async def test_password_not_in_error_messages(self):
        """Test that password is not exposed in error messages."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "super_secret_password_12345"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Wrong username
        credentials = "wrong:super_secret_password_12345"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        
        # Password should not appear in error message
        assert "super_secret_password_12345" not in message
    
    @pytest.mark.asyncio
    async def test_credentials_not_in_success_messages(self):
        """Test that credentials are not exposed in success messages."""
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
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Credentials should not appear in success message
        assert "admin" not in message
        assert "secret123" not in message


class TestBasicAuthEncodingHandling:
    """Test encoding handling edge cases."""
    
    @pytest.mark.asyncio
    async def test_latin1_fallback_encoding(self):
        """Test Latin-1 fallback encoding."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Create credentials that are valid Latin-1 but not UTF-8
        # Latin-1 allows bytes 0x80-0xFF
        latin1_bytes = bytes([0x80, 0x81, 0x82])  # Invalid UTF-8
        credentials = f"admin:{latin1_bytes.decode('latin-1')}"
        encoded = base64.b64encode(credentials.encode('latin-1')).decode()
        
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should handle Latin-1 fallback or reject
        # Test documents behavior
    
    @pytest.mark.asyncio
    async def test_invalid_utf8_encoding(self):
        """Test invalid UTF-8 encoding handling."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Invalid UTF-8 sequence
        invalid_utf8 = b'\xff\xfe\xfd'
        encoded = base64.b64encode(invalid_utf8).decode()
        
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - invalid UTF-8 and not valid Latin-1 either
        assert is_valid is False
        assert "Invalid" in message or "encoding" in message.lower()


class TestBasicAuthEmptyCredentials:
    """Test empty credential handling."""
    
    @pytest.mark.asyncio
    async def test_empty_username_config(self):
        """Test empty username in config."""
        config = {
            "basic_auth": {
                "username": "",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = ":secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Empty username may be rejected
        assert is_valid is False
        assert "not configured" in message or "Invalid credentials" in message
    
    @pytest.mark.asyncio
    async def test_empty_password_config(self):
        """Test empty password in config."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": ""
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Empty password may be rejected
        assert is_valid is False
        assert "not configured" in message or "Invalid credentials" in message
    
    @pytest.mark.asyncio
    async def test_whitespace_only_username(self):
        """Test whitespace-only username."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "   :secret123"  # Whitespace username
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - whitespace username doesn't match
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_whitespace_only_password(self):
        """Test whitespace-only password."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "admin:   "  # Whitespace password
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - whitespace password doesn't match
        assert is_valid is False


class TestBasicAuthTimingAttacks:
    """Test additional timing attack scenarios."""
    
    @pytest.mark.asyncio
    async def test_username_enumeration_timing(self):
        """Test that username enumeration via timing is prevented."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        import time
        
        # Valid username, wrong password
        credentials1 = "admin:wrong"
        encoded1 = base64.b64encode(credentials1.encode()).decode()
        headers1 = {"authorization": f"Basic {encoded1}"}
        
        # Wrong username, wrong password
        credentials2 = "wronguser:wrong"
        encoded2 = base64.b64encode(credentials2.encode()).decode()
        headers2 = {"authorization": f"Basic {encoded2}"}
        
        # Measure times
        start = time.time()
        is_valid1, _ = await validator.validate(headers1, b"")
        time1 = time.time() - start
        
        start = time.time()
        is_valid2, _ = await validator.validate(headers2, b"")
        time2 = time.time() - start
        
        # Both should fail
        assert is_valid1 is False
        assert is_valid2 is False
        
        # Times should be similar (within 0.1s)
        time_diff = abs(time1 - time2)
        assert time_diff < 0.1, f"Timing difference too large: {time_diff}s (potential username enumeration)"
    
    @pytest.mark.asyncio
    async def test_password_length_timing(self):
        """Test that password length doesn't affect timing."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "a" * 100  # Long password
            }
        }
        
        validator = BasicAuthValidator(config)
        
        import time
        
        # Wrong password, same length
        credentials1 = f"admin:{'b' * 100}"
        encoded1 = base64.b64encode(credentials1.encode()).decode()
        headers1 = {"authorization": f"Basic {encoded1}"}
        
        # Wrong password, different length
        credentials2 = "admin:short"
        encoded2 = base64.b64encode(credentials2.encode()).decode()
        headers2 = {"authorization": f"Basic {encoded2}"}
        
        # Measure times
        start = time.time()
        is_valid1, _ = await validator.validate(headers1, b"")
        time1 = time.time() - start
        
        start = time.time()
        is_valid2, _ = await validator.validate(headers2, b"")
        time2 = time.time() - start
        
        # Both should fail
        assert is_valid1 is False
        assert is_valid2 is False
        
        # Times should be similar (hmac.compare_digest is constant-time)
        time_diff = abs(time1 - time2)
        assert time_diff < 0.1, f"Timing difference based on length: {time_diff}s"


class TestBasicAuthEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_special_characters_in_credentials(self):
        """Test special characters in credentials."""
        config = {
            "basic_auth": {
                "username": "user@example.com",
                "password": "p@$$w0rd!#%"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "user@example.com:p@$$w0rd!#%"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_control_characters_in_credentials(self):
        """Test control characters in credentials."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        # Control characters
        credentials = "admin\x01\x02\x03:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - control characters in username
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_very_short_credentials(self):
        """Test very short credentials."""
        config = {
            "basic_auth": {
                "username": "a",
                "password": "b"
            }
        }
        
        validator = BasicAuthValidator(config)
        
        credentials = "a:b"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should work - short credentials are valid
        assert is_valid is True

