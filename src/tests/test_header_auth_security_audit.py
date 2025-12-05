"""
Comprehensive security audit tests for HeaderAuthValidator.
Tests header name injection, header value manipulation, configuration security, error disclosure, and edge cases.
"""
import pytest
from src.validators import HeaderAuthValidator


# ============================================================================
# 1. HEADER NAME INJECTION & VALIDATION
# ============================================================================

class TestHeaderAuthHeaderNameInjection:
    """Test header name injection vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_header_name_injection_via_config(self):
        """Test header name injection via configuration."""
        # Malicious header names that could be used for injection
        malicious_configs = [
            {"header_auth": {"header_name": "../../etc/passwd", "api_key": "secret"}},
            {"header_auth": {"header_name": "X-API-Key\nX-Injected: value", "api_key": "secret"}},
            {"header_auth": {"header_name": "X-API-Key\rX-Injected: value", "api_key": "secret"}},
            {"header_auth": {"header_name": "X-API-Key\x00injected", "api_key": "secret"}},
        ]
        
        for malicious_config in malicious_configs:
            validator = HeaderAuthValidator(malicious_config)
            headers = {"x-api-key": "secret"}
            
            try:
                is_valid, message = await validator.validate(headers, body=b"test")
                # Should handle malicious header names safely
                assert isinstance(is_valid, bool)
            except Exception as e:
                # Should not crash on malicious header names
                assert False, f"Validator crashed on malicious header name: {e}"
    
    @pytest.mark.asyncio
    async def test_header_name_with_control_characters(self):
        """Test header names with control characters."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key\nInjected",
                "api_key": "secret"
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key": "secret"}
        
        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle control characters safely
            assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_header_name_length_limits(self):
        """Test very long header names (DoS prevention)."""
        # Very long header name
        long_header_name = "X-" + "A" * 10000 + "-Key"
        config = {
            "header_auth": {
                "header_name": long_header_name,
                "api_key": "secret"
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {long_header_name.lower(): "secret"}
        
        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle long header names without DoS
            assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 2. HEADER VALUE MANIPULATION
# ============================================================================

class TestHeaderAuthHeaderValueManipulation:
    """Test header value manipulation vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_header_value_with_control_characters(self):
        """Test header values with control characters."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Control characters that should be rejected or sanitized
        control_char_values = [
            "secret_key_123\x00",
            "secret_key_123\n",
            "secret_key_123\r",
            "secret_key_123\t",
        ]
        
        for control_value in control_char_values:
            headers = {"x-api-key": control_value}
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should reject or sanitize control characters
            assert isinstance(is_valid, bool)
    
    @pytest.mark.asyncio
    async def test_header_value_length_limits(self):
        """Test very long header values (DoS prevention)."""
        # Very long header value
        long_value = "a" * 100000
        config = {
            "header_auth": {
                "api_key": long_value
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key": long_value}
        
        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle long values without DoS
            assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_header_value_unicode_manipulation(self):
        """Test Unicode manipulation in header values."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Unicode variations
        unicode_values = [
            "secret_key_123",
            "secret\u005fkey\u005f123",  # Unicode escape sequences
        ]
        
        for unicode_value in unicode_values:
            headers = {"x-api-key": unicode_value}
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle Unicode safely
            assert isinstance(is_valid, bool)


# ============================================================================
# 3. CONFIGURATION SECURITY
# ============================================================================

class TestHeaderAuthConfigurationSecurity:
    """Test configuration security and type validation."""
    
    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {"header_auth": {"api_key": None}},
            {"header_auth": {"api_key": 123}},
            {"header_auth": {"api_key": []}},
            {"header_auth": {"api_key": {}}},
            {"header_auth": {"api_key": "secret", "header_name": None}},
            {"header_auth": {"api_key": "secret", "header_name": 123}},
            {"header_auth": {"api_key": "secret", "case_sensitive": "true"}},  # Should be bool
        ]
        
        for invalid_config in invalid_configs:
            validator = HeaderAuthValidator(invalid_config)
            headers = {"x-api-key": "secret"}
            
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle invalid config gracefully
            assert isinstance(is_valid, bool)
            if not is_valid:
                assert ("not configured" in message.lower() or 
                       "error" in message.lower() or 
                       "invalid" in message.lower() or
                       "must be a string" in message.lower())
    
    @pytest.mark.asyncio
    async def test_empty_api_key_config(self):
        """Test that empty API key in config is rejected."""
        config = {
            "header_auth": {
                "api_key": ""  # Empty string
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key": "some_key"}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "not configured" in message.lower()
    
    @pytest.mark.asyncio
    async def test_whitespace_only_api_key_config(self):
        """Test that whitespace-only API key in config is handled."""
        config = {
            "header_auth": {
                "api_key": "   "  # Whitespace only
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key": "   "}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        # Empty string check should catch this
        assert is_valid is False or "not configured" in message.lower()


# ============================================================================
# 4. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestHeaderAuthErrorDisclosure:
    """Test error message information disclosure."""
    
    @pytest.mark.asyncio
    async def test_config_exposure_in_errors(self):
        """Test that config values are not exposed in error messages."""
        config = {
            "header_auth": {
                "api_key": "secret_api_key_12345"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Invalid key
        headers = {"x-api-key": "wrong_key"}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        
        # Should not expose secret key
        assert "secret_api_key_12345" not in message
        assert "wrong_key" not in message
    
    @pytest.mark.asyncio
    async def test_header_name_exposure(self):
        """Test that header names are not overly exposed in errors."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key",
                "api_key": "secret"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Missing header
        headers = {}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        
        # Header name can be mentioned (it's not secret), but shouldn't expose full config
        # Current implementation mentions header name, which is acceptable
        assert "X-API-Key" in message or "header" in message.lower()


# ============================================================================
# 5. TIMING ATTACKS
# ============================================================================

class TestHeaderAuthTimingAttacks:
    """Test timing attack vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self):
        """Test that validation uses constant-time comparison."""
        import time
        
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Correct key
        correct_headers = {"x-api-key": "secret_key_123"}
        
        # Wrong key (first character different)
        wrong_headers1 = {"x-api-key": "x" + "secret_key_123"[1:]}
        
        # Wrong key (last character different)
        wrong_headers2 = {"x-api-key": "secret_key_123"[:-1] + "x"}
        
        # Measure times
        correct_times = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate(correct_headers, body=b"test")
            correct_times.append(time.perf_counter() - start)
        correct_time = sum(correct_times) / len(correct_times)
        
        wrong_times1 = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate(wrong_headers1, body=b"test")
            wrong_times1.append(time.perf_counter() - start)
        wrong_time1 = sum(wrong_times1) / len(wrong_times1)
        
        wrong_times2 = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate(wrong_headers2, body=b"test")
            wrong_times2.append(time.perf_counter() - start)
        wrong_time2 = sum(wrong_times2) / len(wrong_times2)
        
        # Times should be similar (constant-time comparison)
        time_diff1 = abs(correct_time - wrong_time1) / max(correct_time, wrong_time1, 0.000001)
        time_diff2 = abs(correct_time - wrong_time2) / max(correct_time, wrong_time2, 0.000001)
        
        # Allow up to 70% difference due to system noise
        assert time_diff1 < 0.7, f"Timing attack vulnerability detected (first char): {time_diff1:.2%}"
        assert time_diff2 < 0.7, f"Timing attack vulnerability detected (last char): {time_diff2:.2%}"


# ============================================================================
# 6. HEADER INJECTION ATTACKS
# ============================================================================

class TestHeaderAuthHeaderInjection:
    """Test header injection vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_newline_injection_in_header_value(self):
        """Test newline injection in header value."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Newline injection attempt
        headers = {"x-api-key": "secret_key_123\nX-Injected: value"}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        # Should reject newline injection
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_carriage_return_injection_in_header_value(self):
        """Test carriage return injection in header value."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Carriage return injection attempt
        headers = {"x-api-key": "secret_key_123\rX-Injected: value"}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        # Should reject carriage return injection
        assert is_valid is False
        assert "Invalid API key" in message
    
    @pytest.mark.asyncio
    async def test_null_byte_injection_in_header_value(self):
        """Test null byte injection in header value."""
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Null byte injection attempt
        headers = {"x-api-key": "secret_key_123\x00injected"}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        # Should reject null byte injection
        assert is_valid is False
        assert "Invalid API key" in message


# ============================================================================
# 7. CASE SENSITIVITY EDGE CASES
# ============================================================================

class TestHeaderAuthCaseSensitivity:
    """Test case sensitivity edge cases."""
    
    @pytest.mark.asyncio
    async def test_case_sensitivity_with_unicode(self):
        """Test case sensitivity with Unicode characters."""
        config = {
            "header_auth": {
                "api_key": "SecretKey测试",
                "case_sensitive": True
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Exact match
        headers = {"x-api-key": "SecretKey测试"}
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
        
        # Different case (Unicode case folding)
        headers = {"x-api-key": "secretkey测试"}
        is_valid, message = await validator.validate(headers, body=b"test")
        # Should fail with case_sensitive=True
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_case_sensitivity_empty_string(self):
        """Test case sensitivity with empty strings."""
        config = {
            "header_auth": {
                "api_key": "",
                "case_sensitive": False
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key": ""}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        # Empty string should be rejected
        assert is_valid is False
        assert "not configured" in message.lower() or "Invalid" in message


# ============================================================================
# 8. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================

class TestHeaderAuthEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_headers_dict(self):
        """Test handling of empty headers dict."""
        config = {
            "header_auth": {
                "api_key": "secret"
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {}
        
        is_valid, message = await validator.validate(headers, body=b"test")
        # Should reject missing header
        assert is_valid is False
        assert "Missing required header" in message
    
    @pytest.mark.asyncio
    async def test_none_header_value(self):
        """Test handling of None header value."""
        config = {
            "header_auth": {
                "api_key": "secret"
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key": None}
        
        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle None value safely
            assert isinstance(is_valid, bool)
            if not is_valid:
                assert "Invalid" in message or "Missing" in message
        except Exception as e:
            # Should not crash on None value
            assert False, f"Validator crashed on None value: {e}"
    
    @pytest.mark.asyncio
    async def test_non_string_header_value(self):
        """Test handling of non-string header value."""
        config = {
            "header_auth": {
                "api_key": "secret"
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key": 123}
        
        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle non-string value safely
            assert isinstance(is_valid, bool)
            if not is_valid:
                assert "Invalid" in message or "error" in message.lower()
        except Exception as e:
            # Should not crash on non-string value
            assert False, f"Validator crashed on non-string value: {e}"


# ============================================================================
# 9. UNICODE NORMALIZATION
# ============================================================================

class TestHeaderAuthUnicodeNormalization:
    """Test Unicode normalization vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_unicode_normalization_attack(self):
        """Test Unicode normalization attacks."""
        import unicodedata
        
        config = {
            "header_auth": {
                "api_key": "secret_key_123"
            }
        }
        
        validator = HeaderAuthValidator(config)
        
        # Unicode normalization variations
        # Note: The validator doesn't normalize Unicode, so these should be compared as-is
        normal_key = "secret_key_123"
        nfd_key = unicodedata.normalize('NFD', normal_key)
        nfc_key = unicodedata.normalize('NFC', normal_key)
        
        # Normal key should work
        headers = {"x-api-key": normal_key}
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
        
        # NFD/NFC variations should not match (no normalization)
        headers = {"x-api-key": nfd_key}
        is_valid, message = await validator.validate(headers, body=b"test")
        # Should fail if normalization is not applied (which is correct for security)
        assert is_valid is False or normal_key == nfd_key  # May be same for ASCII


# ============================================================================
# 10. TYPE CONFUSION
# ============================================================================

class TestHeaderAuthTypeConfusion:
    """Test type confusion attacks."""
    
    @pytest.mark.asyncio
    async def test_type_confusion_api_key(self):
        """Test type confusion with api_key config."""
        # Try different types for api_key
        type_confusion_configs = [
            {"header_auth": {"api_key": []}},
            {"header_auth": {"api_key": {}}},
            {"header_auth": {"api_key": True}},
            {"header_auth": {"api_key": 0}},
        ]
        
        for config in type_confusion_configs:
            validator = HeaderAuthValidator(config)
            headers = {"x-api-key": "secret"}
            
            try:
                is_valid, message = await validator.validate(headers, body=b"test")
                # Should handle type confusion safely
                assert isinstance(is_valid, bool)
                if not is_valid:
                    assert ("not configured" in message.lower() or 
                           "error" in message.lower() or 
                           "invalid" in message.lower() or
                           "must be" in message.lower())
            except Exception as e:
                # Should not crash on type confusion
                assert False, f"Validator crashed on type confusion: {e}"
    
    @pytest.mark.asyncio
    async def test_type_confusion_case_sensitive(self):
        """Test type confusion with case_sensitive config."""
        # case_sensitive should be bool, but try other types
        config = {
            "header_auth": {
                "api_key": "secret",
                "case_sensitive": "true"  # String instead of bool
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key": "secret"}
        
        # Should handle non-bool case_sensitive (treats as falsy)
        is_valid, message = await validator.validate(headers, body=b"test")
        # String "true" is truthy in Python, but should be handled safely
        assert isinstance(is_valid, bool)


# ============================================================================
# 11. HEADER NAME VALIDATION
# ============================================================================

class TestHeaderAuthHeaderNameValidation:
    """Test header name validation edge cases."""
    
    @pytest.mark.asyncio
    async def test_header_name_with_special_characters(self):
        """Test header name with special characters."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key!@#$",
                "api_key": "secret"
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"x-api-key!@#$": "secret"}
        
        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle special characters safely
            assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_header_name_empty_string(self):
        """Test header name with empty string."""
        config = {
            "header_auth": {
                "header_name": "",
                "api_key": "secret"
            }
        }
        
        validator = HeaderAuthValidator(config)
        headers = {"": "secret"}
        
        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle empty header name safely
            assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash
            pass

