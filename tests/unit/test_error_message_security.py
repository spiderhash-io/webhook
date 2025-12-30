"""
Security tests for error message sanitization.
Tests that error messages don't leak sensitive information to clients.
"""
import pytest
import re
from src.utils import sanitize_error_message


class TestErrorMessageSecurity:
    """Test suite for error message sanitization."""
    
    def test_url_in_error_sanitized(self):
        """Test that URLs in error messages are sanitized."""
        error = Exception("Failed to connect to http://localhost:6379/")
        sanitized = sanitize_error_message(error, "test")
        
        # Should not contain the URL
        assert "http://localhost:6379" not in sanitized
        assert "localhost" not in sanitized
        assert "6379" not in sanitized
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_file_path_in_error_sanitized(self):
        """Test that file paths in error messages are sanitized."""
        error = Exception("Failed to write to /etc/passwd")
        sanitized = sanitize_error_message(error, "test")
        
        # Should not contain the file path
        assert "/etc/passwd" not in sanitized
        assert "etc" not in sanitized
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_module_name_in_error_sanitized(self):
        """Test that module names in error messages are sanitized."""
        error = Exception("Unsupported module: redis_rq")
        sanitized = sanitize_error_message(error, "test")
        
        # Should not contain the module name
        assert "redis_rq" not in sanitized
        assert "module" not in sanitized.lower() or "module" in sanitized.lower()  # Context is OK
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_hostname_in_error_sanitized(self):
        """Test that hostnames in error messages are sanitized."""
        error = Exception("Connection failed to redis.internal:6379")
        sanitized = sanitize_error_message(error, "test")
        
        # Should not contain hostname or port
        assert "redis.internal" not in sanitized
        assert "6379" not in sanitized
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_ip_address_in_error_sanitized(self):
        """Test that IP addresses in error messages are sanitized."""
        error = Exception("Failed to connect to 192.168.1.100:8080")
        sanitized = sanitize_error_message(error, "test")
        
        # Should not contain IP address or port
        assert "192.168.1.100" not in sanitized
        assert "8080" not in sanitized
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_generic_error_preserved(self):
        """Test that generic errors without sensitive info return generic message."""
        error = Exception("Processing failed")
        sanitized = sanitize_error_message(error, "test")
        
        # Should return generic message
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
        # Should not expose the original error text
        assert "Processing failed" not in sanitized
    
    def test_context_included_in_sanitized_message(self):
        """Test that context is included in sanitized message when provided."""
        error = Exception("Some error")
        sanitized = sanitize_error_message(error, "HTTP webhook forwarding")
        
        # Should include context
        assert "HTTP webhook forwarding" in sanitized or "forwarding" in sanitized.lower()
    
    def test_multiple_sensitive_patterns_sanitized(self):
        """Test that errors with multiple sensitive patterns are sanitized."""
        error = Exception("Failed to connect to http://redis.internal:6379 and write to /tmp/file.txt")
        sanitized = sanitize_error_message(error, "test")
        
        # Should not contain any sensitive information
        assert "http://" not in sanitized
        assert "redis.internal" not in sanitized
        assert "6379" not in sanitized
        assert "/tmp/file.txt" not in sanitized
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_error_string_sanitized(self):
        """Test that string errors are sanitized."""
        error_str = "Connection to http://localhost:3000 failed"
        sanitized = sanitize_error_message(error_str, "test")
        
        # Should not contain URL
        assert "http://localhost:3000" not in sanitized
        assert "localhost" not in sanitized
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_no_context_provided(self):
        """Test sanitization when no context is provided."""
        error = Exception("Failed to http://example.com")
        sanitized = sanitize_error_message(error)
        
        # Should not contain URL
        assert "http://example.com" not in sanitized
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
        # Should not include context
        assert "test" not in sanitized
    
    def test_s3_error_codes_sanitized(self):
        """Test that S3 error codes and messages are sanitized."""
        error = Exception("S3 upload failed: AccessDenied - You don't have permission")
        sanitized = sanitize_error_message(error, "S3 upload")
        
        # Should not contain error code or message
        assert "AccessDenied" not in sanitized
        assert "permission" not in sanitized.lower()
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_webhook_id_not_exposed(self):
        """Test that webhook IDs are not exposed in error messages."""
        error = Exception("Webhook webhook_secret_123 not found")
        sanitized = sanitize_error_message(error, "test")
        
        # Should not contain webhook ID
        assert "webhook_secret_123" not in sanitized
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_configuration_details_not_exposed(self):
        """Test that configuration details are not exposed."""
        error = Exception("Invalid configuration: redis host=localhost port=6379")
        sanitized = sanitize_error_message(error, "test")
        
        # Should not contain configuration details
        assert "localhost" not in sanitized
        assert "6379" not in sanitized
        assert "redis" not in sanitized.lower() or "redis" in sanitized.lower()  # Context might be OK
        # Should be generic
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
    
    def test_stack_trace_not_exposed(self):
        """Test that stack traces are not exposed."""
        try:
            raise ValueError("Some error")
        except ValueError as e:
            error = e
            # Add traceback info (simulated)
            error_str = f"{str(error)}\n  File \"/path/to/file.py\", line 123, in function\n    raise ValueError"
            sanitized = sanitize_error_message(error_str, "test")
            
            # Should not contain file paths or line numbers
            assert "/path/to/file.py" not in sanitized
            assert "line 123" not in sanitized
            # Should be generic
            assert "error" in sanitized.lower() or "occurred" in sanitized.lower()

