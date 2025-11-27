"""
Security tests for query parameter injection prevention.
Tests that query parameters are properly validated and sanitized.
"""
import pytest
from src.validators import QueryParameterAuthValidator


class TestQueryParameterInjection:
    """Test suite for query parameter injection prevention."""
    
    @pytest.fixture
    def config(self):
        """Create a test configuration."""
        return {
            "query_auth": {
                "parameter_name": "api_key",
                "api_key": "secret_key_123",
                "case_sensitive": False
            }
        }
    
    def test_parameter_name_validation(self):
        """Test that parameter names are validated."""
        # Valid names
        valid_names = ["api_key", "token", "auth_key", "key123", "api.key", "api-key"]
        for name in valid_names:
            is_valid, error = QueryParameterAuthValidator._validate_parameter_name(name)
            assert is_valid, f"Valid name '{name}' was rejected: {error}"
        
        # Invalid names
        invalid_names = [
            ("api key", "space"),
            ("api/key", "slash"),
            ("api\\key", "backslash"),
            ("api;key", "semicolon"),
            ("api|key", "pipe"),
            ("api&key", "ampersand"),
            ("api$key", "dollar"),
            ("api`key", "backtick"),
            ("api(key)", "parentheses"),
            ("api[key]", "brackets"),
            ("api{key}", "braces"),
            ("api<key>", "angle brackets"),
            ("api?key", "question mark"),
            ("api!key", "exclamation"),
            ("api@key", "at sign"),
            ("api#key", "hash"),
            ("api%key", "percent"),
            ("api+key", "plus"),
            ("api=key", "equals"),
            ("api,key", "comma"),
            ("api:key", "colon"),
        ]
        for name, reason in invalid_names:
            is_valid, error = QueryParameterAuthValidator._validate_parameter_name(name)
            assert not is_valid, f"Invalid name '{name}' ({reason}) was accepted"
    
    def test_parameter_name_length_limit(self):
        """Test that parameter names have length limits."""
        # Valid length
        valid_name = "a" * 100
        is_valid, error = QueryParameterAuthValidator._validate_parameter_name(valid_name)
        assert is_valid, f"Valid length name was rejected: {error}"
        
        # Too long
        long_name = "a" * 101
        is_valid, error = QueryParameterAuthValidator._validate_parameter_name(long_name)
        assert not is_valid, "Too long name was accepted"
        assert "too long" in error.lower()
    
    def test_parameter_name_control_characters(self):
        """Test that control characters in parameter names are rejected."""
        control_chars = [
            ("api\x00key", "null byte"),
            ("api\nkey", "newline"),
            ("api\rkey", "carriage return"),
            ("api\tkey", "tab"),
        ]
        for name, reason in control_chars:
            is_valid, error = QueryParameterAuthValidator._validate_parameter_name(name)
            assert not is_valid, f"Name with {reason} was accepted"
    
    def test_parameter_name_empty(self):
        """Test that empty parameter names are rejected."""
        is_valid, error = QueryParameterAuthValidator._validate_parameter_name("")
        assert not is_valid
        assert "non-empty" in error.lower() or "empty" in error.lower()
        
        is_valid, error = QueryParameterAuthValidator._validate_parameter_name(None)
        assert not is_valid
    
    def test_parameter_value_sanitization(self):
        """Test that parameter values are sanitized."""
        # Valid values
        valid_values = ["secret_key_123", "token123", "key-123", "key.123", "key_123"]
        for value in valid_values:
            sanitized, is_valid = QueryParameterAuthValidator._sanitize_parameter_value(value)
            assert is_valid, f"Valid value '{value}' was rejected"
            assert sanitized == value, f"Valid value '{value}' was modified: {sanitized}"
        
        # Values with control characters (should be sanitized)
        control_char_values = [
            ("secret\x00key", "secretkey", "null byte"),
            ("secret\nkey", "secretkey", "newline"),
            ("secret\rkey", "secretkey", "carriage return"),
            ("secret\tkey", "secretkey", "tab"),
            ("secret\vkey", "secretkey", "vertical tab"),
            ("secret\fkey", "secretkey", "form feed"),
        ]
        for value, expected, reason in control_char_values:
            sanitized, is_valid = QueryParameterAuthValidator._sanitize_parameter_value(value)
            assert is_valid, f"Value with {reason} was rejected entirely"
            assert sanitized == expected, f"Value with {reason} was not sanitized correctly: '{sanitized}' != '{expected}'"
    
    def test_parameter_value_length_limit(self):
        """Test that parameter values have length limits."""
        # Valid length
        valid_value = "a" * 1000
        sanitized, is_valid = QueryParameterAuthValidator._sanitize_parameter_value(valid_value)
        assert is_valid, "Valid length value was rejected"
        
        # Too long
        long_value = "a" * 1001
        sanitized, is_valid = QueryParameterAuthValidator._sanitize_parameter_value(long_value)
        assert not is_valid, "Too long value was accepted"
    
    def test_parameter_value_non_string(self):
        """Test that non-string parameter values are rejected."""
        non_string_values = [None, 123, [], {}, True]
        for value in non_string_values:
            sanitized, is_valid = QueryParameterAuthValidator._sanitize_parameter_value(value)
            assert not is_valid, f"Non-string value {value} was accepted"
    
    @pytest.mark.asyncio
    async def test_query_params_with_injection_attempts(self, config):
        """Test that injection attempts in query parameters are prevented."""
        injection_attempts = [
            ("api_key", "secret_key_123\x00", "null byte"),
            ("api_key", "secret_key_123\n", "newline"),
            ("api_key", "secret_key_123\r", "carriage return"),
            ("api_key", "secret_key_123\t", "tab"),
            ("api_key", "secret_key_123; DROP TABLE", "SQL injection"),
            ("api_key", "secret_key_123<script>", "XSS attempt"),
            ("api_key", "secret_key_123|command", "command injection"),
            ("api_key", "secret_key_123&command", "command injection"),
        ]
        
        for param_name, param_value, reason in injection_attempts:
            query_params = {param_name: param_value}
            is_valid, message = QueryParameterAuthValidator.validate_query_params(query_params, config)
            # Values are sanitized (control characters removed) before comparison
            # If the sanitized value matches the expected key, validation passes (which is correct)
            # If the sanitized value doesn't match, validation fails
            # For control characters: "secret_key_123\x00" -> "secret_key_123" (matches, so passes)
            # For injection attempts: "secret_key_123; DROP TABLE" -> "secret_key_123; DROP TABLE" (doesn't match, so fails)
            if ';' in param_value or '<' in param_value or '|' in param_value or '&' in param_value:
                # These contain extra characters that won't match after sanitization
                assert not is_valid, f"Injection attempt ({reason}) should fail: sanitized value doesn't match expected key"
            else:
                # Control characters are removed, leaving just the base key which matches
                # This is acceptable - the dangerous characters have been sanitized
                assert is_valid, f"Sanitized value should match expected key after removing control characters ({reason})"
    
    @pytest.mark.asyncio
    async def test_query_params_with_valid_key(self, config):
        """Test that valid keys still work after sanitization."""
        query_params = {"api_key": "secret_key_123"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(query_params, config)
        assert is_valid, f"Valid key was rejected: {message}"
        assert "Valid" in message
    
    @pytest.mark.asyncio
    async def test_query_params_with_sanitized_key(self, config):
        """Test that keys with control characters are sanitized and compared correctly."""
        # Key with control characters that should be sanitized
        query_params = {"api_key": "secret_key_123\x00extra"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(query_params, config)
        # After sanitization, "secret_key_123extra" != "secret_key_123", so should fail
        assert not is_valid, "Sanitized key with control characters should not match"
    
    @pytest.mark.asyncio
    async def test_query_params_invalid_parameter_name_in_config(self):
        """Test that invalid parameter names in config are rejected."""
        invalid_configs = [
            {"query_auth": {"parameter_name": "api key", "api_key": "secret"}},  # Space
            {"query_auth": {"parameter_name": "api/key", "api_key": "secret"}},  # Slash
            {"query_auth": {"parameter_name": "api;key", "api_key": "secret"}},  # Semicolon
            {"query_auth": {"parameter_name": "api\x00key", "api_key": "secret"}},  # Null byte
            {"query_auth": {"parameter_name": "api\nkey", "api_key": "secret"}},  # Newline
        ]
        
        for config in invalid_configs:
            query_params = {"api_key": "secret"}
            is_valid, message = QueryParameterAuthValidator.validate_query_params(query_params, config)
            assert not is_valid, f"Invalid parameter name in config was accepted: {config['query_auth']['parameter_name']}"
            assert "Invalid parameter name" in message or "configuration" in message.lower()
    
    @pytest.mark.asyncio
    async def test_query_params_very_long_value(self, config):
        """Test that very long parameter values are rejected."""
        long_value = "a" * 1001
        query_params = {"api_key": long_value}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(query_params, config)
        assert not is_valid, "Very long parameter value was accepted"
        assert "too long" in message.lower() or "invalid" in message.lower()
    
    @pytest.mark.asyncio
    async def test_query_params_non_string_value(self, config):
        """Test that non-string parameter values are rejected."""
        query_params = {"api_key": 123}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(query_params, config)
        assert not is_valid, "Non-string parameter value was accepted"
        assert "type" in message.lower() or "invalid" in message.lower()
    
    @pytest.mark.asyncio
    async def test_query_params_empty_after_sanitization(self, config):
        """Test that values that become empty after sanitization are rejected."""
        # Value with only control characters
        query_params = {"api_key": "\x00\n\r\t"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(query_params, config)
        assert not is_valid, "Value that becomes empty after sanitization was accepted"
        assert "Invalid" in message or "empty" in message.lower()

