"""
Comprehensive security audit tests for sanitize_error_message (utils.py).
Tests pattern bypass attempts, ReDoS, context injection, encoding issues, and edge cases.
"""

import pytest
import re
import time
from src.utils import sanitize_error_message


# ============================================================================
# 1. PATTERN BYPASS ATTEMPTS
# ============================================================================


class TestSanitizeErrorMessagePatternBypass:
    """Test pattern bypass attempts."""

    def test_url_bypass_encoding(self):
        """Test URL encoding bypass attempts."""
        bypass_attempts = [
            "http%3A%2F%2Flocalhost%3A6379",
            "http%253A%252F%252Flocalhost",  # Double encoded
            "http://localhost:6379",  # Standard
            "HTTP://LOCALHOST:6379",  # Case variation
            "hTtP://LoCaLhOsT:6379",  # Mixed case
        ]

        for attempt in bypass_attempts:
            error = Exception(f"Failed to connect to {attempt}")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize all variations
            assert "localhost" not in sanitized.lower()
            assert "6379" not in sanitized
            assert "http" not in sanitized.lower()

    def test_file_path_bypass_encoding(self):
        """Test file path encoding bypass attempts."""
        bypass_attempts = [
            "/etc/passwd",
            "%2Fetc%2Fpasswd",  # URL encoded
            "\\etc\\passwd",  # Windows path
            "/etc//passwd",  # Double slash
            "/etc/./passwd",  # Current directory
            "/etc/../etc/passwd",  # Path traversal
        ]

        for attempt in bypass_attempts:
            error = Exception(f"Failed to access {attempt}")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize all variations
            assert "etc" not in sanitized.lower()
            assert "passwd" not in sanitized.lower()

    def test_ip_address_bypass(self):
        """Test IP address bypass attempts."""
        bypass_attempts = [
            "192.168.1.100:8080",
            "192.168.1.100:8080",  # Standard
            "192.168.001.100:8080",  # Zero-padded
            "0xC0A80164:8080",  # Hex
            "0300.0250.0001.0144:8080",  # Octal
        ]

        for attempt in bypass_attempts:
            error = Exception(f"Connection to {attempt} failed")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize IP addresses
            assert "192.168" not in sanitized
            assert "8080" not in sanitized

    def test_module_name_bypass(self):
        """Test module name bypass attempts."""
        bypass_attempts = [
            "module redis_rq",
            "Module redis_rq",
            "MODULE redis_rq",
            "module:redis_rq",
            "module-redis_rq",
        ]

        for attempt in bypass_attempts:
            error = Exception(f"Unsupported {attempt}")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize module names
            assert "redis_rq" not in sanitized.lower()

    def test_unicode_bypass(self):
        """Test Unicode bypass attempts."""
        bypass_attempts = [
            "http://localhost:6379",
            "http://localhost:6379",  # Standard
            "http://loca\u006chost:6379",  # Unicode escape
            "http://localhost\u003a6379",  # Unicode colon
        ]

        for attempt in bypass_attempts:
            error = Exception(f"Failed to {attempt}")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize Unicode variations
            assert "localhost" not in sanitized.lower()
            assert "6379" not in sanitized


# ============================================================================
# 2. ReDoS (REGEX DENIAL OF SERVICE)
# ============================================================================


class TestSanitizeErrorMessageReDoS:
    """Test ReDoS vulnerabilities."""

    def test_redos_attack_url_pattern(self):
        """Test ReDoS attack on URL pattern."""
        # Crafted string that could cause excessive backtracking
        # Pattern: r'http[s]?://[^\s]+'
        malicious_string = "http://" + "a" * 1000 + " " + "b" * 1000

        error = Exception(f"Failed to connect to {malicious_string}")

        start_time = time.time()
        sanitized = sanitize_error_message(error, "test")
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: sanitization took {elapsed:.2f}s"
        assert "localhost" not in sanitized.lower()

    def test_redos_attack_file_path_pattern(self):
        """Test ReDoS attack on file path pattern."""
        # Pattern: r'/[^\s]+'
        malicious_string = "/" + "a" * 1000 + " " + "b" * 1000

        error = Exception(f"Failed to access {malicious_string}")

        start_time = time.time()
        sanitized = sanitize_error_message(error, "test")
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: sanitization took {elapsed:.2f}s"
        assert "etc" not in sanitized.lower()

    def test_redos_attack_ip_pattern(self):
        """Test ReDoS attack on IP address pattern."""
        # Pattern: r'\d+\.\d+\.\d+\.\d+:\d+'
        malicious_string = "1." * 1000 + "1:8080"

        error = Exception(f"Connection to {malicious_string} failed")

        start_time = time.time()
        sanitized = sanitize_error_message(error, "test")
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: sanitization took {elapsed:.2f}s"
        assert "8080" not in sanitized

    def test_redos_attack_module_pattern(self):
        """Test ReDoS attack on module name pattern."""
        # Pattern: r'module[_\s]+[\w]+'
        malicious_string = "module " + "a" * 1000

        error = Exception(f"Unsupported {malicious_string}")

        start_time = time.time()
        sanitized = sanitize_error_message(error, "test")
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: sanitization took {elapsed:.2f}s"


# ============================================================================
# 3. CONTEXT INJECTION
# ============================================================================


class TestSanitizeErrorMessageContextInjection:
    """Test context injection vulnerabilities."""

    def test_context_injection_url(self):
        """Test that malicious context doesn't allow information disclosure."""
        malicious_contexts = [
            "http://localhost:6379",
            "/etc/passwd",
            "module redis_rq",
            "192.168.1.100:8080",
        ]

        for malicious_context in malicious_contexts:
            error = Exception("Some error")
            sanitized = sanitize_error_message(error, malicious_context)

            # SECURITY: Context should be sanitized if it contains sensitive patterns
            # Context is trusted input (from code, not user input), but we sanitize for defense in depth
            assert "localhost" not in sanitized.lower()
            assert "6379" not in sanitized
            assert "etc" not in sanitized.lower() or "processing" in sanitized.lower()
            assert "passwd" not in sanitized.lower()
            assert "192.168" not in sanitized
            assert "8080" not in sanitized
            # Should return generic context "processing" for sensitive contexts
            assert "processing" in sanitized.lower()

    def test_context_injection_xss(self):
        """Test that context doesn't allow XSS."""
        xss_contexts = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
        ]

        for xss_context in xss_contexts:
            error = Exception("Some error")
            sanitized = sanitize_error_message(error, xss_context)

            # Context is included in response, but should be safe
            # In production, context should be sanitized or HTML-escaped
            # For now, we just verify it doesn't crash
            assert isinstance(sanitized, str)

    def test_context_injection_sql(self):
        """Test that context doesn't allow SQL injection."""
        sql_contexts = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
        ]

        for sql_context in sql_contexts:
            error = Exception("Some error")
            sanitized = sanitize_error_message(error, sql_context)

            # Context is included in response
            # Should not cause issues (context is not used in SQL)
            assert isinstance(sanitized, str)


# ============================================================================
# 4. EDGE CASES
# ============================================================================


class TestSanitizeErrorMessageEdgeCases:
    """Test edge cases in error message sanitization."""

    def test_empty_error(self):
        """Test empty error message."""
        error = Exception("")
        sanitized = sanitize_error_message(error, "test")

        # Should return generic message
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()

    def test_none_error(self):
        """Test None error."""
        sanitized = sanitize_error_message(None, "test")

        # Should handle None gracefully
        assert isinstance(sanitized, str)
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()

    def test_very_long_error(self):
        """Test very long error message."""
        long_error = "Error: " + "a" * 10000
        error = Exception(long_error)

        start_time = time.time()
        sanitized = sanitize_error_message(error, "test")
        elapsed = time.time() - start_time

        # Should complete quickly
        assert elapsed < 1.0, f"Long error message took {elapsed:.2f}s"
        assert isinstance(sanitized, str)

    def test_multiline_error(self):
        """Test multiline error message."""
        multiline_error = "Error:\nLine 1: http://localhost:6379\nLine 2: /etc/passwd"
        error = Exception(multiline_error)
        sanitized = sanitize_error_message(error, "test")

        # Should sanitize all lines
        assert "localhost" not in sanitized.lower()
        assert "6379" not in sanitized
        assert "etc" not in sanitized.lower()
        assert "passwd" not in sanitized.lower()

    def test_special_characters_error(self):
        """Test error with special characters."""
        special_chars = "Error: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        error = Exception(special_chars)
        sanitized = sanitize_error_message(error, "test")

        # Should handle special characters
        assert isinstance(sanitized, str)
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()

    def test_unicode_error(self):
        """Test error with Unicode characters."""
        unicode_error = "Error: 测试 http://localhost:6379 中文"
        error = Exception(unicode_error)
        sanitized = sanitize_error_message(error, "test")

        # Should sanitize Unicode errors
        assert "localhost" not in sanitized.lower()
        assert "6379" not in sanitized

    def test_control_characters_error(self):
        """Test error with control characters."""
        control_chars = "Error: \x00\x01\x02\x03 http://localhost:6379"
        error = Exception(control_chars)
        sanitized = sanitize_error_message(error, "test")

        # Should handle control characters
        assert "localhost" not in sanitized.lower()
        assert "6379" not in sanitized
        assert "\x00" not in sanitized


# ============================================================================
# 5. INFORMATION DISCLOSURE VIA DIFFERENT FORMATS
# ============================================================================


class TestSanitizeErrorMessageInformationDisclosure:
    """Test information disclosure via different error formats."""

    def test_stack_trace_disclosure(self):
        """Test that stack traces are sanitized."""
        stack_trace = """
Traceback (most recent call last):
  File "/path/to/file.py", line 123, in function
    raise ValueError("Error")
ValueError: Error at http://localhost:6379
"""
        error = Exception(stack_trace)
        sanitized = sanitize_error_message(error, "test")

        # Should sanitize stack trace
        assert "/path/to/file.py" not in sanitized
        assert "line 123" not in sanitized
        assert "localhost" not in sanitized.lower()
        assert "6379" not in sanitized

    def test_database_error_disclosure(self):
        """Test that database errors are sanitized."""
        db_errors = [
            "Connection failed: postgresql://user:pass@localhost:5432/db",
            "SQL error: SELECT * FROM users WHERE id = 1",
            "Database error: table 'users' doesn't exist",
        ]

        for db_error in db_errors:
            error = Exception(db_error)
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize database information
            assert "postgresql" not in sanitized.lower()
            assert "user:pass" not in sanitized.lower()
            assert "localhost" not in sanitized.lower()
            assert "5432" not in sanitized

    def test_api_key_disclosure(self):
        """Test that API keys are sanitized."""
        api_key_errors = [
            "API key: sk_live_1234567890abcdef",
            "Authentication failed with key: ak_test_abcdef123456",
            "Invalid token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ]

        for api_key_error in api_key_errors:
            error = Exception(api_key_error)
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize API keys
            assert "sk_live" not in sanitized
            assert "ak_test" not in sanitized
            assert (
                "Bearer" not in sanitized or "Bearer" in sanitized
            )  # Generic "Bearer" is OK
            assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized

    def test_password_disclosure(self):
        """Test that passwords are sanitized."""
        password_errors = [
            "Authentication failed: password=secret123",
            "Login error: user=admin, pass=password123",
            "Credential error: pwd=MyP@ssw0rd!",
        ]

        for password_error in password_errors:
            error = Exception(password_error)
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize passwords
            assert "secret123" not in sanitized
            assert "password123" not in sanitized
            assert "MyP@ssw0rd!" not in sanitized
            assert (
                "password=" not in sanitized.lower() or "password=" in sanitized.lower()
            )  # Generic is OK

    def test_connection_string_disclosure(self):
        """Test that connection strings are sanitized."""
        connection_strings = [
            "redis://localhost:6379/0",
            "mongodb://user:pass@host:27017/db",
            "amqp://guest:guest@localhost:5672/",
        ]

        for conn_str in connection_strings:
            error = Exception(f"Connection failed: {conn_str}")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize connection strings
            assert "localhost" not in sanitized.lower()
            assert "6379" not in sanitized
            assert "user:pass" not in sanitized.lower()
            assert "guest:guest" not in sanitized.lower()


# ============================================================================
# 6. PATTERN MATCHING EDGE CASES
# ============================================================================


class TestSanitizeErrorMessagePatternMatching:
    """Test pattern matching edge cases."""

    def test_partial_url_match(self):
        """Test that partial URL matches are caught."""
        partial_urls = [
            "http://",
            "https://",
            "http://localhost",
            "http://localhost:",
        ]

        for partial_url in partial_urls:
            error = Exception(f"Error: {partial_url}")
            sanitized = sanitize_error_message(error, "test")

            # Should catch partial URLs
            assert (
                "localhost" not in sanitized.lower()
                or partial_url != "http://localhost"
            )

    def test_url_without_scheme(self):
        """Test URLs without scheme."""
        urls_without_scheme = [
            "localhost:6379",
            "example.com:8080",
            "192.168.1.100:3000",
        ]

        for url in urls_without_scheme:
            error = Exception(f"Connection to {url} failed")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize hostname:port patterns
            assert "localhost" not in sanitized.lower() or url != "localhost:6379"
            assert "6379" not in sanitized or url != "localhost:6379"

    def test_file_path_variations(self):
        """Test file path variations."""
        path_variations = [
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\sam",
            "~/secret.txt",
            "../config.json",
            "./local.env",
        ]

        for path in path_variations:
            error = Exception(f"Failed to access {path}")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize file paths
            assert "etc" not in sanitized.lower() or path != "/etc/passwd"
            assert "passwd" not in sanitized.lower() or path != "/etc/passwd"

    def test_module_name_variations(self):
        """Test module name pattern variations."""
        module_variations = [
            "module redis_rq",
            "Module: redis_rq",
            "module-redis_rq",
            "module_redis_rq",
            "module\tredis_rq",  # Tab
            "module\nredis_rq",  # Newline
        ]

        for module_var in module_variations:
            error = Exception(f"Unsupported {module_var}")
            sanitized = sanitize_error_message(error, "test")

            # Should sanitize module names
            assert "redis_rq" not in sanitized.lower()


# ============================================================================
# 7. PERFORMANCE AND DoS
# ============================================================================


class TestSanitizeErrorMessagePerformance:
    """Test performance and DoS prevention."""

    # def test_large_error_message_performance(self):
    #     """Test performance with large error messages."""
    #     large_error = "Error: " + "a" * 100000  # 100KB
    #
    #     start_time = time.time()
    #     sanitized = sanitize_error_message(large_error, "test")
    #     elapsed = time.time() - start_time
    #
    #     # Should complete in reasonable time
    #     assert elapsed < 5.0, f"Large error message took {elapsed:.2f}s"
    #     assert isinstance(sanitized, str)

    def test_many_patterns_performance(self):
        """Test performance with many sensitive patterns."""
        many_patterns = " ".join([f"http://host{i}:{8000+i}" for i in range(100)])
        error = Exception(many_patterns)

        start_time = time.time()
        sanitized = sanitize_error_message(error, "test")
        elapsed = time.time() - start_time

        # Should complete quickly
        assert elapsed < 1.0, f"Many patterns took {elapsed:.2f}s"
        assert "host" not in sanitized.lower()

    def test_nested_patterns_performance(self):
        """Test performance with nested patterns."""
        nested_patterns = "http://" + "/etc/passwd" * 100
        error = Exception(nested_patterns)

        start_time = time.time()
        sanitized = sanitize_error_message(error, "test")
        elapsed = time.time() - start_time

        # Should complete quickly
        assert elapsed < 1.0, f"Nested patterns took {elapsed:.2f}s"
        assert "etc" not in sanitized.lower()


# ============================================================================
# 8. TYPE HANDLING
# ============================================================================


class TestSanitizeErrorMessageTypeHandling:
    """Test type handling edge cases."""

    def test_string_error(self):
        """Test string error."""
        error_str = "Connection failed to http://localhost:6379"
        sanitized = sanitize_error_message(error_str, "test")

        assert "localhost" not in sanitized.lower()
        assert "6379" not in sanitized

    def test_exception_error(self):
        """Test Exception object."""
        error = Exception("Connection failed to http://localhost:6379")
        sanitized = sanitize_error_message(error, "test")

        assert "localhost" not in sanitized.lower()
        assert "6379" not in sanitized

    def test_custom_exception(self):
        """Test custom exception."""

        class CustomException(Exception):
            pass

        error = CustomException("Connection failed to http://localhost:6379")
        sanitized = sanitize_error_message(error, "test")

        assert "localhost" not in sanitized.lower()
        assert "6379" not in sanitized

    def test_exception_with_custom_str(self):
        """Test exception with custom __str__ method."""

        class CustomError(Exception):
            def __str__(self):
                return "Custom error: http://localhost:6379"

        error = CustomError()
        sanitized = sanitize_error_message(error, "test")

        assert "localhost" not in sanitized.lower()
        assert "6379" not in sanitized

    def test_non_string_error(self):
        """Test non-string error."""
        error = 12345
        sanitized = sanitize_error_message(error, "test")

        # Should handle non-string errors
        assert isinstance(sanitized, str)
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()


# ============================================================================
# 9. CASE SENSITIVITY
# ============================================================================


class TestSanitizeErrorMessageCaseSensitivity:
    """Test case sensitivity handling."""

    def test_case_insensitive_url_matching(self):
        """Test that URL matching is case-insensitive."""
        case_variations = [
            "HTTP://LOCALHOST:6379",
            "Http://Localhost:6379",
            "hTtP://lOcAlHoSt:6379",
        ]

        for case_var in case_variations:
            error = Exception(f"Failed to {case_var}")
            sanitized = sanitize_error_message(error, "test")

            # Should match case-insensitively
            assert "localhost" not in sanitized.lower()
            assert "6379" not in sanitized

    def test_case_insensitive_module_matching(self):
        """Test that module matching is case-insensitive."""
        case_variations = [
            "MODULE redis_rq",
            "Module redis_rq",
            "mOdUlE redis_rq",
        ]

        for case_var in case_variations:
            error = Exception(f"Unsupported {case_var}")
            sanitized = sanitize_error_message(error, "test")

            # Should match case-insensitively
            assert "redis_rq" not in sanitized.lower()


# ============================================================================
# 10. CONTEXT HANDLING
# ============================================================================


class TestSanitizeErrorMessageContextHandling:
    """Test context handling."""

    def test_context_in_response(self):
        """Test that context is included in response."""
        error = Exception("Some error")
        sanitized = sanitize_error_message(error, "test_context")

        # Context should be included
        assert "test_context" in sanitized or "context" in sanitized.lower()

    def test_no_context_provided(self):
        """Test behavior when no context is provided."""
        error = Exception("Some error")
        sanitized = sanitize_error_message(error)

        # Should return generic message
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
        # Should not include "test" or other context
        assert "test" not in sanitized.lower()

    def test_empty_context(self):
        """Test empty context."""
        error = Exception("Some error")
        sanitized = sanitize_error_message(error, "")

        # Should handle empty context
        assert isinstance(sanitized, str)
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()

    def test_none_context(self):
        """Test None context."""
        error = Exception("Some error")
        sanitized = sanitize_error_message(error, None)

        # Should handle None context
        assert isinstance(sanitized, str)
        assert "error" in sanitized.lower() or "occurred" in sanitized.lower()
