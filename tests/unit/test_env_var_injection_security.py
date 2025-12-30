"""
Security tests for environment variable injection prevention.
Tests that environment variable values are sanitized to prevent injection attacks.
"""
import pytest
import os
from src.utils import load_env_vars, _sanitize_env_value


class TestEnvVarInjectionSecurity:
    """Test suite for environment variable injection prevention."""
    
    def test_command_injection_prevention(self):
        """Test that command injection patterns are removed from env values."""
        # Set environment variable with command injection
        os.environ['MALICIOUS_VAR'] = 'value; rm -rf /'
        
        config = {
            "host": "{$MALICIOUS_VAR}"
        }
        
        result = load_env_vars(config)
        
        # Semicolon should be removed
        assert ';' not in result["host"]
        # Command keywords should be removed
        assert 'rm' not in result["host"].lower()
        assert 'rm -rf' not in result["host"].lower()
        # Safe parts should remain
        assert 'value' in result["host"]
    
    def test_null_byte_removal(self):
        """Test that null bytes are removed from env values."""
        # Note: Python's os.environ doesn't allow null bytes, so we test the function directly
        # Set environment variable (without null byte since os.environ rejects it)
        os.environ['NULL_VAR'] = 'valueinjection'
        
        config = {
            "host": "{$NULL_VAR}"
        }
        
        result = load_env_vars(config)
        
        # Test the sanitization function directly with null byte
        from src.utils import _sanitize_env_value
        sanitized = _sanitize_env_value('value\x00injection', 'test')
        assert '\x00' not in sanitized
        assert 'value' in sanitized
        assert 'injection' in sanitized
    
    def test_url_injection_prevention(self):
        """Test that dangerous URL schemes are removed from env values."""
        # Set environment variable with JavaScript injection
        os.environ['MALICIOUS_URL'] = 'javascript:alert(1)'
        
        config = {
            "url": "{$MALICIOUS_URL}"
        }
        
        result = load_env_vars(config)
        
        # JavaScript scheme should be removed
        assert not result["url"].lower().startswith('javascript:')
    
    def test_sql_injection_prevention(self):
        """Test that SQL injection patterns are removed from env values."""
        # Set environment variable with SQL injection
        os.environ['MALICIOUS_SQL'] = "'; DROP TABLE users; --"
        
        config = {
            "table": "{$MALICIOUS_SQL}"
        }
        
        result = load_env_vars(config)
        
        # SQL injection patterns should be removed
        assert "';" not in result["table"]
        assert "--" not in result["table"]
        assert "DROP" not in result["table"].upper()
    
    def test_path_traversal_prevention(self):
        """Test that path traversal patterns are removed from env values."""
        # Set environment variable with path traversal
        os.environ['MALICIOUS_PATH'] = '../../../etc/passwd'
        
        config = {
            "path": "{$MALICIOUS_PATH}"
        }
        
        result = load_env_vars(config)
        
        # Path traversal should be removed
        assert '..' not in result["path"]
    
    def test_backtick_command_injection(self):
        """Test that backtick command execution is prevented."""
        # Set environment variable with backtick injection
        os.environ['MALICIOUS_VAR'] = 'value`rm -rf /`'
        
        config = {
            "host": "{$MALICIOUS_VAR}"
        }
        
        result = load_env_vars(config)
        
        # Backticks should be removed
        assert '`' not in result["host"]
    
    def test_command_substitution_prevention(self):
        """Test that command substitution patterns are removed."""
        # Set environment variable with command substitution
        os.environ['MALICIOUS_VAR'] = 'value$(rm -rf /)'
        
        config = {
            "host": "{$MALICIOUS_VAR}"
        }
        
        result = load_env_vars(config)
        
        # Command substitution should be removed
        assert '$(' not in result["host"]
    
    def test_embedded_env_var_injection_prevention(self):
        """Test that embedded env vars are sanitized."""
        # Set environment variable with injection
        os.environ['MALICIOUS_HOST'] = 'evil.com; rm -rf /'
        
        config = {
            "url": "http://{$MALICIOUS_HOST}:8080/api"
        }
        
        result = load_env_vars(config)
        
        # Injection should be removed from embedded variable
        assert ';' not in result["url"]
        # Command keywords should be removed
        assert 'rm' not in result["url"].lower()
        assert 'rm -rf' not in result["url"].lower()
    
    def test_multiple_dangerous_patterns(self):
        """Test that multiple dangerous patterns are all removed."""
        # Set environment variable with multiple injection patterns
        os.environ['MALICIOUS_VAR'] = 'value; rm -rf / | cat /etc/passwd &'
        
        config = {
            "host": "{$MALICIOUS_VAR}"
        }
        
        result = load_env_vars(config)
        
        # All dangerous characters should be removed
        assert ';' not in result["host"]
        assert '|' not in result["host"]
        assert '&' not in result["host"]
    
    def test_length_limit_enforced(self):
        """Test that overly long env values are truncated."""
        # Set environment variable with very long value
        long_value = 'a' * 5000
        os.environ['LONG_VAR'] = long_value
        
        config = {
            "host": "{$LONG_VAR}"
        }
        
        result = load_env_vars(config)
        
        # Value should be truncated to max length
        assert len(result["host"]) <= 4096
    
    def test_default_value_sanitization(self):
        """Test that default values are also sanitized."""
        # Use default value with injection
        config = {
            "host": "{$NONEXISTENT_VAR:evil.com; rm -rf /}"
        }
        
        result = load_env_vars(config)
        
        # Default value should be sanitized
        assert ';' not in result["host"]
        # Command keywords should be removed
        assert 'rm' not in result["host"].lower()
        assert 'rm -rf' not in result["host"].lower()
    
    def test_valid_env_values_preserved(self):
        """Test that valid environment variable values are preserved."""
        # Set valid environment variable
        os.environ['VALID_HOST'] = 'example.com'
        
        config = {
            "host": "{$VALID_HOST}"
        }
        
        result = load_env_vars(config)
        
        # Valid value should be preserved
        assert result["host"] == 'example.com'
    
    def test_valid_embedded_env_values_preserved(self):
        """Test that valid embedded env vars are preserved."""
        # Set valid environment variables
        os.environ['VALID_HOST'] = 'api.example.com'
        os.environ['VALID_PORT'] = '8080'
        
        config = {
            "url": "http://{$VALID_HOST}:{$VALID_PORT}/api"
        }
        
        result = load_env_vars(config)
        
        # Valid embedded values should be preserved
        assert result["url"] == "http://api.example.com:8080/api"
    
    def test_sanitize_env_value_direct(self):
        """Test _sanitize_env_value function directly."""
        # Test null byte removal
        result = _sanitize_env_value('value\x00injection', 'test')
        assert '\x00' not in result
        
        # Test command injection removal
        result = _sanitize_env_value('value; rm -rf /', 'test')
        assert ';' not in result
        
        # Test URL injection removal
        result = _sanitize_env_value('javascript:alert(1)', 'url')
        assert not result.lower().startswith('javascript:')
        
        # Test SQL injection removal
        result = _sanitize_env_value("'; DROP TABLE users; --", 'table')
        assert "';" not in result
        assert "--" not in result
    
    def test_context_aware_sanitization(self):
        """Test that sanitization is context-aware."""
        # URL context should remove dangerous schemes
        result = _sanitize_env_value('javascript:alert(1)', 'url')
        assert not result.lower().startswith('javascript:')
        # Parentheses should also be removed (command injection)
        assert '(' not in result
        assert ')' not in result
        
        # SQL context should remove SQL injection patterns
        result = _sanitize_env_value("'; DROP TABLE users; --", 'table_name')
        assert "';" not in result
        assert "--" not in result
        # SQL keywords should be removed
        assert 'drop' not in result.lower()
        assert 'table' not in result.lower()
        
        # Non-URL context should still sanitize command injection
        result = _sanitize_env_value('javascript:alert(1)', 'host')
        # Parentheses should be removed (command injection)
        assert '(' not in result
        assert ')' not in result
    
    def test_nested_structure_sanitization(self):
        """Test that nested structures are sanitized."""
        os.environ['MALICIOUS_VAR'] = 'evil.com; rm -rf /'
        
        config = {
            "webhook": {
                "module-config": {
                    "host": "{$MALICIOUS_VAR}"
                }
            }
        }
        
        result = load_env_vars(config)
        
        # Nested value should be sanitized
        assert ';' not in result["webhook"]["module-config"]["host"]
    
    def test_list_sanitization(self):
        """Test that list values are sanitized."""
        os.environ['MALICIOUS_VAR'] = 'value; rm -rf /'
        
        config = {
            "hosts": ["{$MALICIOUS_VAR}", "other.com"]
        }
        
        result = load_env_vars(config)
        
        # List value should be sanitized
        assert ';' not in result["hosts"][0]
    
    def test_multiple_env_vars_in_string(self):
        """Test that multiple env vars in one string are all sanitized."""
        os.environ['HOST'] = 'evil.com; rm -rf /'
        os.environ['PORT'] = '8080; cat /etc/passwd'
        
        config = {
            "url": "http://{$HOST}:{$PORT}/api"
        }
        
        result = load_env_vars(config)
        
        # Both embedded values should be sanitized
        assert ';' not in result["url"]
        # Command keywords should be removed
        assert 'rm' not in result["url"].lower()
        assert 'rm -rf' not in result["url"].lower()
        assert 'cat' not in result["url"].lower()
    
    def test_special_characters_handling(self):
        """Test that special characters are handled correctly."""
        # Set environment variable with various special characters
        os.environ['SPECIAL_VAR'] = 'value!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        config = {
            "host": "{$SPECIAL_VAR}"
        }
        
        result = load_env_vars(config)
        
        # Dangerous command separators should be removed
        assert ';' not in result["host"]
        assert '|' not in result["host"]
        assert '&' not in result["host"]
        # Other special characters may remain (not all are dangerous)
    
    def test_unicode_injection_prevention(self):
        """Test that Unicode-based injection attempts are handled."""
        # Note: os.environ doesn't allow null bytes, so we test the function directly
        from src.utils import _sanitize_env_value
        
        # Test Unicode null byte
        result = _sanitize_env_value('value\u0000injection', 'test')
        assert '\x00' not in result
        assert '\u0000' not in result
        
        # Test with regular string (os.environ compatible)
        os.environ['UNICODE_VAR'] = 'valueinjection'
        config = {
            "host": "{$UNICODE_VAR}"
        }
        result = load_env_vars(config)
        assert result["host"] == 'valueinjection'

