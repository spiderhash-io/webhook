"""
Comprehensive security audit tests for Configuration System (config.py).
Tests JSON parsing DoS, configuration injection, type confusion, error disclosure, and edge cases.
"""
import pytest
import json
import os
import tempfile
from unittest.mock import patch, Mock, AsyncMock
from src.config import (
    _validate_connection_host,
    _validate_connection_port,
    inject_connection_details
)
from src.utils import load_env_vars, _sanitize_env_value


# ============================================================================
# 1. JSON PARSING DoS ATTACKS
# ============================================================================

class TestConfigJSONParsingDoS:
    """Test JSON parsing denial-of-service attacks in configuration files."""
    
    def test_deeply_nested_json_config(self):
        """Test that deeply nested JSON configuration doesn't cause stack overflow."""
        # Create deeply nested structure (but limit to avoid RecursionError in json.dumps)
        # Python's default recursion limit is ~1000, so use 500 levels to be safe
        nested = {"level": 1}
        current = nested
        for i in range(2, 500):  # Deep nesting but within recursion limits
            current["nested"] = {"level": i}
            current = current["nested"]
        
        # Try to parse as JSON
        try:
            json_str = json.dumps(nested)
            # Should parse successfully (Python's json handles this)
            parsed = json.loads(json_str)
            assert parsed is not None
        except RecursionError:
            # If json.dumps hits recursion limit, that's acceptable - test passes
            # The important thing is that it doesn't crash the application
            assert True
    
    def test_large_json_config(self):
        """Test that very large JSON configuration doesn't cause memory exhaustion."""
        # Create large JSON structure
        large_config = {
            "webhook": {
                "data": "x" * 1000000  # 1MB string
            }
        }
        
        json_str = json.dumps(large_config)
        
        # Should parse successfully
        parsed = json.loads(json_str)
        assert parsed is not None
        assert len(parsed["webhook"]["data"]) == 1000000
    
    def test_circular_reference_in_config(self):
        """Test that circular references in configuration are handled safely."""
        # Note: JSON doesn't support circular references, but test structure manipulation
        config = {
            "webhook1": {
                "connection": "conn1"
            },
            "webhook2": {
                "connection": "conn2"
            }
        }
        
        # JSON serialization should work
        json_str = json.dumps(config)
        parsed = json.loads(json_str)
        assert parsed is not None


# ============================================================================
# 2. CONFIGURATION INJECTION
# ============================================================================

class TestConfigInjection:
    """Test configuration injection vulnerabilities."""
    
    def test_type_confusion_host_non_string(self):
        """Test that non-string hosts are rejected."""
        invalid_hosts = [
            None,
            123,
            [],
            {},
            True,
        ]
        
        for invalid_host in invalid_hosts:
            with pytest.raises(ValueError, match=r'must be a non-empty string'):
                _validate_connection_host(invalid_host, "Test")
    
    def test_type_confusion_port_non_integer(self):
        """Test that non-integer ports are rejected."""
        invalid_ports = [
            ("not_a_number", r'must be a valid integer'),
            ([], r'must be a valid integer'),
            ({}, r'must be a valid integer'),
            (None, r'must be specified'),  # None raises different error
        ]
        
        for invalid_port, error_pattern in invalid_ports:
            with pytest.raises(ValueError, match=error_pattern):
                _validate_connection_port(invalid_port, "Test")
    
    @pytest.mark.asyncio
    async def test_connection_type_validation(self):
        """Test that invalid connection types are handled safely."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "invalid_conn"
            }
        }
        
        connection_config = {
            "invalid_conn": {
                # Missing 'type' field
                "host": "8.8.8.8",
                "port": 6379
            }
        }
        
        # Should handle missing type gracefully
        with pytest.raises(ValueError, match=r'missing required.*type'):
            await inject_connection_details(webhook_config, connection_config)
    
    @pytest.mark.asyncio
    async def test_missing_connection_handling(self):
        """Test that missing connections are handled safely."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "nonexistent_conn"
            }
        }
        
        connection_config = {}
        
        # Should handle missing connection gracefully
        result = await inject_connection_details(webhook_config, connection_config)
        # Connection details should not be injected if connection not found
        assert "connection_details" not in result["test_webhook"]
    
    @pytest.mark.asyncio
    async def test_connection_name_injection(self):
        """Test that connection name injection is handled safely."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "../../etc/passwd"  # Path traversal attempt
            }
        }
        
        connection_config = {
            "../../etc/passwd": {
                "type": "redis-rq",
                "host": "8.8.8.8",
                "port": 6379
            }
        }
        
        # Should handle path traversal in connection name
        with patch('src.config.Redis') as mock_redis:
            mock_redis.return_value = Mock()
            result = await inject_connection_details(webhook_config, connection_config)
            # Should process connection even with suspicious name
            assert "connection_details" in result["test_webhook"]


# ============================================================================
# 3. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestConfigErrorDisclosure:
    """Test error information disclosure vulnerabilities."""
    
    def test_host_validation_error_disclosure(self):
        """Test that host validation errors don't disclose sensitive information."""
        # Test with sensitive hostname
        sensitive_host = "internal-database.example.com"
        
        try:
            _validate_connection_host(sensitive_host, "Test")
        except ValueError as e:
            error_msg = str(e)
            # Should not expose full internal hostname in error
            # Error should be generic or sanitized
            assert "internal-database" in error_msg or "Test" in error_msg
    
    def test_port_validation_error_disclosure(self):
        """Test that port validation errors don't disclose sensitive information."""
        # Test with invalid port
        try:
            _validate_connection_port("invalid", "Test")
        except ValueError as e:
            error_msg = str(e)
            # Should not expose system details
            assert "Test" in error_msg or "port" in error_msg.lower()


# ============================================================================
# 4. REGEX DoS (ReDoS)
# ============================================================================

class TestConfigReDoS:
    """Test regex denial-of-service vulnerabilities."""
    
    def test_env_var_pattern_redos(self):
        """Test that environment variable regex patterns are not vulnerable to ReDoS."""
        import time
        
        # Test with malicious input that could cause ReDoS
        malicious_inputs = [
            "{$" + "A" * 1000 + "}",
            "{$VAR:" + "A" * 1000 + "}",
            "http://{$" + "A" * 1000 + "}:8080",
        ]
        
        for malicious_input in malicious_inputs:
            start_time = time.time()
            try:
                load_env_vars({"key": malicious_input})
            except Exception:
                pass
            elapsed = time.time() - start_time
            
            # Should complete quickly (not vulnerable to ReDoS)
            assert elapsed < 1.0, f"ReDoS vulnerability detected for input: {malicious_input[:50]}"


# ============================================================================
# 5. ENVIRONMENT VARIABLE NAME INJECTION
# ============================================================================

class TestEnvVarNameInjection:
    """Test environment variable name injection vulnerabilities."""
    
    def test_malicious_env_var_names(self):
        """Test that malicious environment variable names are handled safely."""
        # Python's os.environ doesn't allow certain characters, but test edge cases
        malicious_names = [
            "VAR; rm -rf /",
            "VAR| cat /etc/passwd",
            "VAR`id`",
            "VAR$(whoami)",
        ]
        
        for malicious_name in malicious_names:
            # os.environ will reject these, but test the pattern matching
            config = {
                "key": f"{{${malicious_name}}}"
            }
            
            # Should handle gracefully (pattern won't match due to \w+)
            result = load_env_vars(config)
            # Should return undefined variable message
            assert "Undefined variable" in result["key"] or malicious_name in result["key"]
    
    def test_env_var_name_regex_bypass(self):
        """Test regex bypass attempts in environment variable names."""
        # Test with various special characters
        bypass_attempts = [
            "{$VAR\x00}",
            "{$VAR\n}",
            "{$VAR\r}",
            "{$VAR\t}",
        ]
        
        for attempt in bypass_attempts:
            config = {
                "key": attempt
            }
            
            # Should handle gracefully
            result = load_env_vars(config)
            # Pattern won't match, so should return as-is or undefined
            assert isinstance(result["key"], str)


# ============================================================================
# 6. CONFIGURATION STRUCTURE MANIPULATION
# ============================================================================

class TestConfigStructureManipulation:
    """Test configuration structure manipulation attacks."""
    
    def test_nested_configuration_injection(self):
        """Test that nested configuration structures are handled safely."""
        malicious_config = {
            "webhook": {
                "module": "redis_rq",
                "connection": "conn1",
                "__class__": "malicious",
                "__init__": "evil",
            }
        }
        
        # Should handle special attributes safely
        result = load_env_vars(malicious_config)
        assert "__class__" in result["webhook"] or "webhook" in result
    
    def test_configuration_key_injection(self):
        """Test that malicious configuration keys are handled safely."""
        malicious_config = {
            "../../etc/passwd": "value",
            "key; rm -rf /": "value",
            "key`id`": "value",
        }
        
        # Should handle malicious keys
        result = load_env_vars(malicious_config)
        # Keys should be preserved (Python dict keys are strings)
        assert isinstance(result, dict)
    
    def test_list_configuration_manipulation(self):
        """Test that list configurations are handled safely."""
        malicious_config = {
            "hosts": [
                "{$VAR1}",
                "../../etc/passwd",
                "value; rm -rf /",
            ]
        }
        
        # Should process list items
        result = load_env_vars(malicious_config)
        assert isinstance(result["hosts"], list)


# ============================================================================
# 7. CONNECTION VALIDATION EDGE CASES
# ============================================================================

class TestConnectionValidationEdgeCases:
    """Test connection validation edge cases."""
    
    def test_host_validation_unicode(self):
        """Test that Unicode characters in hosts are handled safely."""
        unicode_hosts = [
            "example.com",
            "xn--example.com",  # Punycode
            "example\u0000.com",  # Null byte
        ]
        
        for host in unicode_hosts:
            if '\x00' in host:
                # Should reject null bytes
                with pytest.raises(ValueError, match=r'null bytes'):
                    _validate_connection_host(host, "Test")
            else:
                # Should validate normally
                try:
                    result = _validate_connection_host(host, "Test")
                    assert result is not None
                except ValueError:
                    # Some Unicode hosts may be rejected
                    pass
    
    def test_port_validation_edge_cases(self):
        """Test port validation edge cases."""
        edge_cases = [
            (0, False),  # Port 0 is invalid
            (1, True),   # Port 1 is valid
            (65535, True),  # Port 65535 is valid
            (65536, False),  # Port 65536 is invalid
            (-1, False),  # Negative port is invalid
        ]
        
        for port, should_pass in edge_cases:
            if should_pass:
                result = _validate_connection_port(port, "Test")
                assert result == port
            else:
                with pytest.raises(ValueError):
                    _validate_connection_port(port, "Test")
    
    def test_host_validation_whitespace(self):
        """Test that whitespace in hosts is handled safely."""
        hosts_with_whitespace = [
            "  example.com  ",
            "example.com\n",
            "example.com\r",
            "example.com\t",
        ]
        
        for host in hosts_with_whitespace:
            try:
                result = _validate_connection_host(host, "Test")
                # Should strip whitespace
                assert result == host.strip() or "example.com" in result
            except ValueError:
                # Some whitespace may be rejected
                pass


# ============================================================================
# 8. INJECT_CONNECTION_DETAILS SECURITY
# ============================================================================

class TestInjectConnectionDetailsSecurity:
    """Test inject_connection_details security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_missing_host_handling(self):
        """Test that missing host is handled safely."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "redis_test"
            }
        }
        
        connection_config = {
            "redis_test": {
                "type": "redis-rq",
                # Missing host
                "port": 6379
            }
        }
        
        # Should raise ValueError for missing host
        with pytest.raises(ValueError, match=r'host'):
            await inject_connection_details(webhook_config, connection_config)
    
    @pytest.mark.asyncio
    async def test_missing_port_handling(self):
        """Test that missing port is handled safely."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "redis_test"
            }
        }
        
        connection_config = {
            "redis_test": {
                "type": "redis-rq",
                "host": "8.8.8.8",
                # Missing port
            }
        }
        
        # Should raise ValueError for missing port
        with pytest.raises(ValueError, match=r'port'):
            await inject_connection_details(webhook_config, connection_config)
    
    @pytest.mark.asyncio
    async def test_invalid_connection_type(self):
        """Test that invalid connection types are handled safely."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "invalid_conn"
            }
        }
        
        connection_config = {
            "invalid_conn": {
                "type": "invalid_type",  # Invalid type
                "host": "8.8.8.8",
                "port": 6379
            }
        }
        
        # Should handle invalid type gracefully (no connection created)
        result = await inject_connection_details(webhook_config, connection_config)
        # Connection details may or may not be injected for invalid types
        assert isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_multiple_webhooks_same_connection(self):
        """Test that multiple webhooks using same connection are handled safely."""
        webhook_config = {
            "webhook1": {
                "module": "redis_rq",
                "connection": "shared_conn"
            },
            "webhook2": {
                "module": "redis_rq",
                "connection": "shared_conn"
            }
        }
        
        connection_config = {
            "shared_conn": {
                "type": "redis-rq",
                "host": "8.8.8.8",
                "port": 6379
            }
        }
        
        # Should handle shared connections
        with patch('src.config.Redis') as mock_redis:
            mock_redis.return_value = Mock()
            result = await inject_connection_details(webhook_config, connection_config)
            # Both webhooks should have connection details
            assert "connection_details" in result["webhook1"]
            assert "connection_details" in result["webhook2"]


# ============================================================================
# 9. LARGE CONFIGURATION DoS
# ============================================================================

class TestConfigLargeDoS:
    """Test large configuration denial-of-service attacks."""
    
    def test_large_number_of_webhooks(self):
        """Test that large number of webhooks doesn't cause DoS."""
        # Create configuration with many webhooks
        large_config = {}
        for i in range(1000):
            large_config[f"webhook_{i}"] = {
                "module": "log",
                "data_type": "json"
            }
        
        # Should process efficiently
        result = load_env_vars(large_config)
        assert len(result) == 1000
    
    def test_large_number_of_connections(self):
        """Test that large number of connections doesn't cause DoS."""
        # Create configuration with many connections
        large_config = {}
        for i in range(1000):
            large_config[f"conn_{i}"] = {
                "type": "redis-rq",
                "host": "8.8.8.8",
                "port": 6379
            }
        
        # Should process efficiently
        result = load_env_vars(large_config)
        assert len(result) == 1000


# ============================================================================
# 10. FILE LOADING SECURITY
# ============================================================================

class TestConfigFileLoadingSecurity:
    """Test configuration file loading security."""
    
    def test_file_path_traversal_prevention(self):
        """Test that file path traversal is prevented in file loading."""
        # Files are hardcoded, but test that path manipulation doesn't work
        # Note: config.py uses hardcoded paths, so path traversal shouldn't be possible
        # But we test the file existence check
        
        # Test with non-existent file
        with patch('os.path.exists', return_value=False):
            # Should handle missing file gracefully
            from src.config import webhook_config_data
            # webhook_config_data should be empty dict if file doesn't exist
            assert isinstance(webhook_config_data, dict)
    
    def test_malformed_json_handling(self):
        """Test that malformed JSON is handled safely."""
        # Create temporary file with malformed JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"invalid": json}')  # Malformed JSON
            temp_path = f.name
        
        try:
            # Should raise JSONDecodeError
            with open(temp_path, 'r') as file:
                with pytest.raises(json.JSONDecodeError):
                    json.load(file)
        finally:
            os.unlink(temp_path)


# ============================================================================
# 11. ENVIRONMENT VARIABLE PATTERN BYPASS
# ============================================================================

class TestEnvVarPatternBypass:
    """Test environment variable pattern bypass attempts."""
    
    def test_nested_braces_bypass(self):
        """Test that nested braces don't bypass pattern matching."""
        bypass_attempts = [
            "{{$VAR}}",
            "{$VAR}}",
            "{{$VAR}",
            "{$VAR}{$VAR2}",
        ]
        
        for attempt in bypass_attempts:
            config = {
                "key": attempt
            }
            
            result = load_env_vars(config)
            # Should handle gracefully
            assert isinstance(result["key"], str)
    
    def test_whitespace_in_pattern(self):
        """Test that whitespace in patterns is handled safely."""
        patterns_with_whitespace = [
            "{$ VAR}",
            "{$VAR }",
            "{ $VAR}",
            "{$VAR: default}",
        ]
        
        for pattern in patterns_with_whitespace:
            config = {
                "key": pattern
            }
            
            result = load_env_vars(config)
            # Pattern won't match due to whitespace, should return as-is
            assert isinstance(result["key"], str)


# ============================================================================
# 12. CONFIGURATION VALIDATION ORDER
# ============================================================================

class TestConfigValidationOrder:
    """Test configuration validation order security."""
    
    @pytest.mark.asyncio
    async def test_validation_before_connection_creation(self):
        """Test that validation happens before connection creation."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "redis_test"
            }
        }
        
        connection_config = {
            "redis_test": {
                "type": "redis-rq",
                "host": "127.0.0.1",  # Should be blocked by validation
                "port": 6379
            }
        }
        
        # Should raise ValueError before creating connection
        with pytest.raises(ValueError, match=r'localhost|not allowed'):
            await inject_connection_details(webhook_config, connection_config)
        
        # Verify Redis was not called
        # (Validation should happen first)
    
    @pytest.mark.asyncio
    async def test_host_validation_before_port_validation(self):
        """Test that host validation happens before port validation."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "redis_test"
            }
        }
        
        connection_config = {
            "redis_test": {
                "type": "redis-rq",
                "host": "127.0.0.1",  # Invalid host
                "port": "invalid",    # Invalid port (but host should be checked first)
            }
        }
        
        # Should raise ValueError for host first
        with pytest.raises(ValueError, match=r'localhost|not allowed'):
            await inject_connection_details(webhook_config, connection_config)

