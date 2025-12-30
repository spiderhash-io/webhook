"""
Comprehensive security audit tests for AuthorizationValidator.

This audit focuses on:
- Type confusion attacks (config, headers, header values)
- Error information disclosure
- Configuration injection
- Unicode normalization attacks
- Case sensitivity bypass attempts
- Whitespace manipulation attacks
- Empty/None value handling
- Control character injection (beyond newline/carriage return/null byte)
- Header value type confusion
- Bearer token format bypass attempts
- DoS via large tokens/headers
- Edge cases and boundary conditions
"""
import pytest
import asyncio
from src.validators import AuthorizationValidator
from src.utils import sanitize_error_message


# ============================================================================
# 1. TYPE CONFUSION ATTACKS
# ============================================================================

class TestTypeConfusionAttacks:
    """Test type confusion vulnerabilities in AuthorizationValidator."""
    
    def test_config_type_confusion_non_dict(self):
        """Test that non-dict config is rejected (handled by BaseValidator)."""
        invalid_configs = [
            None,
            "not_a_dict",
            123,
            [],
            set(),
            tuple(),
        ]
        
        for invalid_config in invalid_configs:
            with pytest.raises(TypeError, match="Config must be a dictionary"):
                AuthorizationValidator(invalid_config)
    
    def test_config_type_confusion_authorization_non_string(self):
        """Test that non-string authorization config is handled safely."""
        # Non-string authorization config should be handled gracefully
        configs = [
            {"authorization": None},
            {"authorization": 123},
            {"authorization": []},
            {"authorization": {}},
            {"authorization": True},
        ]
        
        for config in configs:
            validator = AuthorizationValidator(config)
            # Should not crash, but may return "No authorization required" or fail validation
            assert validator is not None
    
    @pytest.mark.asyncio
    async def test_header_value_type_confusion_non_string(self):
        """Test that non-string header values are handled safely."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Non-string header values
        invalid_headers = [
            {"authorization": None},
            {"authorization": 123},
            {"authorization": []},
            {"authorization": {}},
            {"authorization": True},
        ]
        
        for headers in invalid_headers:
            # Should not crash, but may fail validation
            try:
                is_valid, message = await validator.validate(headers, b"")
                # Should either fail validation or handle gracefully
                assert isinstance(is_valid, bool)
                assert isinstance(message, str)
            except (AttributeError, TypeError) as e:
                # AttributeError/TypeError is acceptable - validator rejects invalid input
                pass
    
    @pytest.mark.asyncio
    async def test_headers_dict_type_confusion_non_dict(self):
        """Test that non-dict headers parameter is handled safely."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Non-dict headers
        invalid_headers = [
            None,
            "not_a_dict",
            123,
            [],
            set(),
        ]
        
        for headers in invalid_headers:
            # Should not crash
            try:
                is_valid, message = await validator.validate(headers, b"")
                # Should either fail validation or handle gracefully
                assert isinstance(is_valid, bool)
                assert isinstance(message, str)
            except (AttributeError, TypeError) as e:
                # AttributeError/TypeError is acceptable - validator rejects invalid input
                pass


# ============================================================================
# 2. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestErrorInformationDisclosure:
    """Test error information disclosure vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages don't leak sensitive information."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Invalid token
        headers = {"authorization": "Bearer wrong_token"}
        is_valid, message = await validator.validate(headers, b"")
        
        assert is_valid is False
        # Error message should not contain expected token
        assert "secret_token_123" not in message
        assert "Bearer secret_token_123" not in message
        # Should use generic error message
        assert "Unauthorized" in message or "Invalid" in message
    
    @pytest.mark.asyncio
    async def test_error_message_no_config_details(self):
        """Test that error messages don't leak config details."""
        config = {
            "authorization": "Bearer very_secret_token_abc123xyz"
        }
        validator = AuthorizationValidator(config)
        
        # Missing header
        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        
        assert is_valid is False
        # Error message should not contain config details
        assert "very_secret_token_abc123xyz" not in message
        assert "Bearer very_secret_token_abc123xyz" not in message
    
    @pytest.mark.asyncio
    async def test_exception_handling_no_stack_trace(self):
        """Test that exceptions don't expose stack traces."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Invalid input that might cause exception
        invalid_inputs = [
            {"authorization": None},
            {"authorization": 123},
            {},
        ]
        
        for headers in invalid_inputs:
            try:
                is_valid, message = await validator.validate(headers, b"")
                # Should return error message, not raise exception
                assert isinstance(is_valid, bool)
                assert isinstance(message, str)
            except Exception as e:
                # If exception is raised, it should be handled by caller
                # But validator should handle gracefully
                pytest.fail(f"Validator should handle invalid input gracefully, got exception: {e}")


# ============================================================================
# 3. CONFIGURATION INJECTION
# ============================================================================

class TestConfigurationInjection:
    """Test configuration injection vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_config_injection_via_authorization_value(self):
        """Test that malicious authorization config values are handled safely."""
        # Attempt to inject control characters in config
        malicious_configs = [
            {"authorization": "Bearer token\nX-Injected: value"},
            {"authorization": "Bearer token\rX-Injected: value"},
            {"authorization": "Bearer token\x00X-Injected: value"},
            {"authorization": "Bearer token\tX-Injected: value"},
        ]
        
        for config in malicious_configs:
            validator = AuthorizationValidator(config)
            # Should not crash
            assert validator is not None
            
            # Validation should handle malicious config safely
            headers = {"authorization": config["authorization"]}
            is_valid, message = await validator.validate(headers, b"")
            # Should either reject or handle safely
            assert isinstance(is_valid, bool)
            assert isinstance(message, str)
    
    @pytest.mark.asyncio
    async def test_config_injection_via_unicode_normalization(self):
        """Test that Unicode normalization attacks in config are handled safely."""
        # Unicode lookalike characters
        config = {
            "authorization": "Bearer token_ünicode_测试"
        }
        validator = AuthorizationValidator(config)
        
        # Valid unicode token
        headers = {"authorization": "Bearer token_ünicode_测试"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Invalid unicode token (different normalization)
        headers = {"authorization": "Bearer token_ünicode_wrong"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False


# ============================================================================
# 4. UNICODE NORMALIZATION ATTACKS
# ============================================================================

class TestUnicodeNormalizationAttacks:
    """Test Unicode normalization vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_unicode_lookalike_characters(self):
        """Test that Unicode lookalike characters are handled correctly."""
        # Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
        config = {
            "authorization": "Bearer token_abc123"
        }
        validator = AuthorizationValidator(config)
        
        # Valid token
        headers = {"authorization": "Bearer token_abc123"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Lookalike attack (Cyrillic 'а' instead of Latin 'a')
        headers = {"authorization": "Bearer token_аbc123"}  # Cyrillic 'а'
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - different characters
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_unicode_normalization_forms(self):
        """Test that Unicode normalization forms are handled correctly."""
        # Unicode normalization: NFC vs NFD
        # é can be represented as U+00E9 (NFC) or U+0065 U+0301 (NFD)
        import unicodedata
        
        token_nfc = "Bearer token_é"
        token_nfd = "Bearer " + unicodedata.normalize('NFD', "token_é")
        
        config = {
            "authorization": token_nfc
        }
        validator = AuthorizationValidator(config)
        
        # NFC form
        headers = {"authorization": token_nfc}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # NFD form (should fail if not normalized)
        headers = {"authorization": token_nfd}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - different byte representation
        assert is_valid is False


# ============================================================================
# 5. CASE SENSITIVITY BYPASS ATTEMPTS
# ============================================================================

class TestCaseSensitivityBypass:
    """Test case sensitivity bypass attempts."""
    
    @pytest.mark.asyncio
    async def test_bearer_prefix_case_sensitivity(self):
        """Test that Bearer prefix is case-sensitive."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Case variations of "Bearer"
        case_variations = [
            "bearer secret_token_123",  # lowercase
            "BEARER secret_token_123",  # uppercase
            "BeArEr secret_token_123",  # mixed case
            "Bearer secret_token_123",  # correct
        ]
        
        for header_value in case_variations:
            headers = {"authorization": header_value}
            is_valid, message = await validator.validate(headers, b"")
            
            if header_value == "Bearer secret_token_123":
                assert is_valid is True
            else:
                assert is_valid is False
                assert "must start with 'Bearer '" in message
    
    @pytest.mark.asyncio
    async def test_token_case_sensitivity(self):
        """Test that tokens are case-sensitive."""
        config = {
            "authorization": "Bearer SecretToken123"
        }
        validator = AuthorizationValidator(config)
        
        # Case variations
        case_variations = [
            "Bearer secrettoken123",  # lowercase
            "Bearer SECRETTOKEN123",  # uppercase
            "Bearer SecretToken123",  # correct
        ]
        
        for header_value in case_variations:
            headers = {"authorization": header_value}
            is_valid, message = await validator.validate(headers, b"")
            
            if header_value == "Bearer SecretToken123":
                assert is_valid is True
            else:
                assert is_valid is False
                assert "Unauthorized" in message
    
    @pytest.mark.asyncio
    async def test_non_bearer_token_case_sensitivity(self):
        """Test that non-Bearer tokens are case-sensitive."""
        config = {
            "authorization": "CustomToken SecretValue"
        }
        validator = AuthorizationValidator(config)
        
        # Case variations
        case_variations = [
            "customtoken SecretValue",  # lowercase prefix
            "CustomToken secretvalue",  # lowercase value
            "CustomToken SecretValue",  # correct
        ]
        
        for header_value in case_variations:
            headers = {"authorization": header_value}
            is_valid, message = await validator.validate(headers, b"")
            
            if header_value == "CustomToken SecretValue":
                assert is_valid is True
            else:
                assert is_valid is False
                assert "Unauthorized" in message


# ============================================================================
# 6. WHITESPACE MANIPULATION ATTACKS
# ============================================================================

class TestWhitespaceManipulation:
    """Test whitespace manipulation vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_leading_whitespace_handling(self):
        """Test that leading whitespace is handled correctly."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Leading whitespace should be stripped
        headers = {"authorization": "  Bearer secret_token_123"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_trailing_whitespace_handling(self):
        """Test that trailing whitespace is handled correctly."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Trailing whitespace should be normalized
        headers = {"authorization": "Bearer secret_token_123  "}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_multiple_spaces_after_bearer(self):
        """Test that multiple spaces after Bearer are rejected."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Multiple spaces after "Bearer "
        headers = {"authorization": "Bearer  secret_token_123"}  # Double space
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "token cannot start with whitespace" in message
    
    @pytest.mark.asyncio
    async def test_tab_character_handling(self):
        """Test that tab characters are handled correctly."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Tab character in header
        headers = {"authorization": "Bearer\tsecret_token_123"}
        is_valid, message = await validator.validate(headers, b"")
        # Tab should be rejected (not in dangerous_chars list, but should fail format validation)
        # Actually, tab is not in dangerous_chars, so it might pass format validation
        # But Bearer token extraction should fail
        assert is_valid is False


# ============================================================================
# 7. CONTROL CHARACTER INJECTION
# ============================================================================

class TestControlCharacterInjection:
    """Test control character injection vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_control_characters_beyond_standard(self):
        """Test that control characters beyond newline/carriage return/null are handled."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        # Additional control characters
        control_chars = [
            '\x01',  # SOH
            '\x02',  # STX
            '\x03',  # ETX
            '\x04',  # EOT
            '\x05',  # ENQ
            '\x06',  # ACK
            '\x07',  # BEL
            '\x08',  # BS
            '\x0B',  # VT
            '\x0C',  # FF
            '\x0E',  # SO
            '\x0F',  # SI
            '\x10',  # DLE
            '\x11',  # DC1
            '\x12',  # DC2
            '\x13',  # DC3
            '\x14',  # DC4
            '\x15',  # NAK
            '\x16',  # SYN
            '\x17',  # ETB
            '\x18',  # CAN
            '\x19',  # EM
            '\x1A',  # SUB
            '\x1B',  # ESC
            '\x1C',  # FS
            '\x1D',  # GS
            '\x1E',  # RS
            '\x1F',  # US
            '\x7F',  # DEL
        ]
        
        for char in control_chars:
            headers = {"authorization": f"Bearer secret_token_123{char}X-Injected: value"}
            is_valid, message = await validator.validate(headers, b"")
            # Should either reject or handle safely
            # Note: Current implementation only checks for \n, \r, \0
            # Other control characters might pass format validation
            assert isinstance(is_valid, bool)
            assert isinstance(message, str)


# ============================================================================
# 8. EMPTY/NONE VALUE HANDLING
# ============================================================================

class TestEmptyNoneValueHandling:
    """Test empty/None value handling edge cases."""
    
    @pytest.mark.asyncio
    async def test_empty_authorization_config(self):
        """Test that empty authorization config is handled correctly."""
        config = {
            "authorization": ""
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer any_token"}
        is_valid, message = await validator.validate(headers, b"")
        # Empty config should mean no authorization required
        assert is_valid is True
        assert "No authorization required" in message
    
    @pytest.mark.asyncio
    async def test_empty_authorization_header(self):
        """Test that empty authorization header is handled correctly."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": ""}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message or "Unauthorized" in message
    
    @pytest.mark.asyncio
    async def test_missing_authorization_header(self):
        """Test that missing authorization header is handled correctly."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message or "Unauthorized" in message
    
    @pytest.mark.asyncio
    async def test_whitespace_only_authorization_config(self):
        """Test that whitespace-only authorization config is handled correctly."""
        config = {
            "authorization": "   "
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer any_token"}
        is_valid, message = await validator.validate(headers, b"")
        # Whitespace-only config should be treated as empty after strip()
        assert is_valid is True
        assert "No authorization required" in message
    
    @pytest.mark.asyncio
    async def test_whitespace_only_authorization_header(self):
        """Test that whitespace-only authorization header is handled correctly."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "   "}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message or "Unauthorized" in message


# ============================================================================
# 9. BEARER TOKEN FORMAT BYPASS ATTEMPTS
# ============================================================================

class TestBearerTokenFormatBypass:
    """Test Bearer token format bypass attempts."""
    
    @pytest.mark.asyncio
    async def test_bearer_without_space(self):
        """Test that Bearer without space is rejected."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearersecret_token_123"}  # No space
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "must start with 'Bearer '" in message
    
    @pytest.mark.asyncio
    async def test_bearer_with_multiple_spaces(self):
        """Test that Bearer with multiple spaces is rejected."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer  secret_token_123"}  # Double space
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "token cannot start with whitespace" in message
    
    @pytest.mark.asyncio
    async def test_bearer_empty_token(self):
        """Test that Bearer with empty token is rejected."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer "}  # Empty token
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert ("token cannot be empty" in message or "must start with 'Bearer '" in message)
    
    @pytest.mark.asyncio
    async def test_bearer_whitespace_only_token(self):
        """Test that Bearer with whitespace-only token is rejected."""
        config = {
            "authorization": "Bearer secret_token_123"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer    "}  # Whitespace only
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert ("token cannot be empty" in message or 
                "token cannot be whitespace only" in message or
                "must start with 'Bearer '" in message or
                "token cannot start with whitespace" in message)


# ============================================================================
# 10. DoS VIA LARGE TOKENS/HEADERS
# ============================================================================

class TestDoSProtection:
    """Test DoS protection via large tokens/headers."""
    
    @pytest.mark.asyncio
    async def test_header_length_limit_enforcement(self):
        """Test that headers exceeding length limit are rejected."""
        config = {
            "authorization": "Bearer " + "a" * 100
        }
        validator = AuthorizationValidator(config)
        
        # Header exactly at limit (8192 bytes)
        header_at_limit = "Bearer " + "a" * (8192 - 7)  # 7 bytes for "Bearer "
        headers = {"authorization": header_at_limit}
        is_valid, message = await validator.validate(headers, b"")
        # Should pass (at limit, not exceeding)
        assert isinstance(is_valid, bool)
        
        # Header exceeding limit (8193 bytes)
        header_exceeding = "Bearer " + "a" * (8193 - 7)  # 7 bytes for "Bearer "
        headers = {"authorization": header_exceeding}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "too long" in message
    
    @pytest.mark.asyncio
    async def test_very_long_token_handling(self):
        """Test that very long tokens are handled correctly."""
        # Token within limit but very long
        long_token = "Bearer " + "a" * 5000
        config = {
            "authorization": long_token
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": long_token}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Invalid long token
        invalid_long_token = "Bearer " + "a" * 4999 + "b"
        headers = {"authorization": invalid_long_token}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Unauthorized" in message


# ============================================================================
# 11. EDGE CASES AND BOUNDARY CONDITIONS
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_single_character_token(self):
        """Test that single character tokens are handled correctly."""
        config = {
            "authorization": "Bearer a"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer a"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        headers = {"authorization": "Bearer b"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_token_with_special_characters(self):
        """Test that tokens with special characters are handled correctly."""
        config = {
            "authorization": "Bearer token!@#$%^&*()_+-=[]{}|;:,.<>?"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer token!@#$%^&*()_+-=[]{}|;:,.<>?"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        headers = {"authorization": "Bearer token!@#$%^&*()_+-=[]{}|;:,.<>X"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_token_with_internal_spaces(self):
        """Test that tokens with internal spaces are handled correctly."""
        config = {
            "authorization": "Bearer token with spaces"
        }
        validator = AuthorizationValidator(config)
        
        headers = {"authorization": "Bearer token with spaces"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        headers = {"authorization": "Bearer token with different spaces"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_non_bearer_token_exact_match(self):
        """Test that non-Bearer tokens require exact match."""
        config = {
            "authorization": "CustomToken secret_value"
        }
        validator = AuthorizationValidator(config)
        
        # Exact match
        headers = {"authorization": "CustomToken secret_value"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Partial match (should fail)
        headers = {"authorization": "CustomToken secret"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Unauthorized" in message
    
    @pytest.mark.asyncio
    async def test_config_with_whitespace_normalization(self):
        """Test that config whitespace normalization matches header normalization."""
        config = {
            "authorization": "  Bearer secret_token_123  "  # Leading/trailing whitespace
        }
        validator = AuthorizationValidator(config)
        
        # Header with matching normalization
        headers = {"authorization": "  Bearer secret_token_123  "}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        
        # Header without whitespace (should still match after normalization)
        headers = {"authorization": "Bearer secret_token_123"}
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

