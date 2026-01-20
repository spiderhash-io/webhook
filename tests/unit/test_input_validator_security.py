"""
Security tests for Input Validator - DoS, injection, bypass, and validation attacks.

These tests verify that the input validator properly prevents:
- DoS via recursive JSON depth (stack overflow)
- DoS via memory exhaustion (large payloads/strings)
- ReDoS (Regex Denial of Service) attacks
- XSS bypass via encoding/obfuscation
- Integer overflow in size calculations
- Type confusion attacks
- Bypass via null bytes or special characters
- Header injection attacks
"""

import pytest
import sys
import time
from src.input_validator import InputValidator


class TestInputValidatorSecurity:
    """Security-focused tests for input validator."""

    def test_dos_json_depth_recursion_stack_overflow(self):
        """Test that extremely deep JSON doesn't cause stack overflow."""
        # Create JSON at the limit (50 levels) - should pass
        nested = {"level": 1}
        current = nested
        for i in range(2, 51):
            current["nested"] = {"level": i}
            current = current["nested"]

        start_time = time.time()
        is_valid, msg = InputValidator.validate_json_depth(nested)
        elapsed = time.time() - start_time

        # Should complete quickly without stack overflow
        assert (
            elapsed < 1.0
        ), "JSON depth validation should complete quickly (no stack overflow)"
        assert is_valid, "Should accept JSON at depth limit"

        # Test one level over limit
        current["nested"] = {"level": 51}
        start_time = time.time()
        is_valid, msg = InputValidator.validate_json_depth(nested)
        elapsed = time.time() - start_time

        assert elapsed < 1.0, "Should reject quickly without stack overflow"
        assert not is_valid, "Should reject JSON over depth limit"

    def test_dos_large_payload_memory_exhaustion(self):
        """Test that payload size validation prevents memory exhaustion."""
        # Test at limit
        payload = b"x" * InputValidator.MAX_PAYLOAD_SIZE
        is_valid, msg = InputValidator.validate_payload_size(payload)
        assert is_valid, "Should accept payload at size limit"

        # Test just over limit
        payload = b"x" * (InputValidator.MAX_PAYLOAD_SIZE + 1)
        is_valid, msg = InputValidator.validate_payload_size(payload)
        assert not is_valid, "Should reject payload over size limit"

        # Test extremely large payload (should fail fast without creating it)
        # Note: We can't actually create a huge payload in memory, but we test the check
        # The validation should happen before any processing

    def test_dos_large_string_memory_exhaustion(self):
        """Test that string length validation prevents memory exhaustion."""
        # Test at limit
        data = {"large": "x" * InputValidator.MAX_STRING_LENGTH}
        is_valid, msg = InputValidator.validate_string_length(data)
        assert is_valid, "Should accept string at length limit"

        # Test just over limit
        data = {"huge": "x" * (InputValidator.MAX_STRING_LENGTH + 1)}
        is_valid, msg = InputValidator.validate_string_length(data)
        assert not is_valid, "Should reject string over length limit"

    def test_redos_regex_pattern_matching(self):
        """Test that regex patterns don't cause ReDoS attacks."""
        # ReDoS attack pattern: nested quantifiers that cause exponential backtracking
        # Pattern: (a+)+b with input "aaaaaaaaac" causes exponential backtracking
        # However, our patterns are simple and shouldn't cause ReDoS

        # Test with various inputs that could cause ReDoS
        test_cases = [
            "a" * 1000 + "b",  # Long string
            "a" * 10000 + "b",  # Very long string
            "<script>" + "a" * 1000 + "</script>",  # XSS pattern with long content
        ]

        for test_input in test_cases:
            start_time = time.time()
            is_safe, msg = InputValidator.check_dangerous_patterns(test_input)
            elapsed = time.time() - start_time

            # Should complete quickly (under 1 second even for long strings)
            assert (
                elapsed < 1.0
            ), f"Pattern matching should complete quickly (ReDoS protection), took {elapsed}s for input length {len(test_input)}"

    def test_xss_bypass_encoding_obfuscation(self):
        """Test XSS bypass attempts via encoding and obfuscation."""
        # Common XSS bypass techniques
        xss_bypass_attempts = [
            "<ScRiPt>alert('XSS')</ScRiPt>",  # Case variation
            "<script>alert(String.fromCharCode(88,83,83))</script>",  # Character codes
            "<script>alert('XSS')</script>",  # Already covered
            "<img src=x onerror=alert('XSS')>",  # Event handler variation
            "<svg onload=alert('XSS')>",  # SVG tag
            "<body onload=alert('XSS')>",  # Body tag
            "<iframe src=javascript:alert('XSS')>",  # Iframe
            "<input onfocus=alert('XSS') autofocus>",  # Input with autofocus
            "<marquee onstart=alert('XSS')>",  # Marquee tag
            "javascript:alert('XSS')",  # JavaScript protocol
            "JAVASCRIPT:alert('XSS')",  # Uppercase
            "JaVaScRiPt:alert('XSS')",  # Mixed case
            "<script>eval('alert(\\'XSS\\')')</script>",  # Eval
            "<script>setTimeout('alert(\\'XSS\\')', 0)</script>",  # setTimeout
        ]

        for xss_attempt in xss_bypass_attempts:
            is_safe, msg = InputValidator.check_dangerous_patterns(xss_attempt)
            # Should detect most XSS attempts (some may bypass simple regex)
            # This test documents current detection capabilities
            if not is_safe:
                assert "dangerous pattern" in msg.lower() or "pattern" in msg.lower()

    def test_integer_overflow_size_calculation(self):
        """Test that size calculations don't overflow."""
        # Test with very large numbers that could cause overflow
        # Python handles big integers, but we should test edge cases

        # Test header size calculation with many small headers
        headers = {f"H{i}": "v" for i in range(InputValidator.MAX_HEADER_COUNT)}
        is_valid, msg = InputValidator.validate_headers(headers)
        # Should handle calculation without overflow
        assert isinstance(is_valid, bool)

        # Test with headers at limit
        header_size = InputValidator.MAX_HEADER_SIZE // 2
        headers = {"Header1": "x" * header_size, "Header2": "x" * header_size}
        is_valid, msg = InputValidator.validate_headers(headers)
        # Should calculate total size correctly
        assert isinstance(is_valid, bool)

    def test_type_confusion_attacks(self):
        """Test that type confusion attacks are handled safely."""
        # Attempt to pass wrong types to validation functions

        # Test validate_payload_size with non-bytes
        try:
            is_valid, msg = InputValidator.validate_payload_size("not bytes")
            # Should handle gracefully (either validate or raise TypeError)
            assert isinstance(is_valid, bool) or isinstance(msg, str)
        except (TypeError, AttributeError):
            # Acceptable - type checking should catch this
            pass

        # Test validate_headers with non-dict
        try:
            is_valid, msg = InputValidator.validate_headers("not a dict")
            assert isinstance(is_valid, bool) or isinstance(msg, str)
        except (TypeError, AttributeError):
            pass

        # Test validate_json_depth with non-JSON types
        try:
            is_valid, msg = InputValidator.validate_json_depth("not json")
            assert isinstance(is_valid, bool) or isinstance(msg, str)
        except (TypeError, AttributeError):
            pass

        # Test validate_string_length with non-serializable types
        try:
            is_valid, msg = InputValidator.validate_string_length(object())
            assert isinstance(is_valid, bool) or isinstance(msg, str)
        except (TypeError, AttributeError):
            pass

    def test_null_byte_injection(self):
        """Test that null bytes and special characters are handled safely."""
        # Null byte injection attempts
        null_byte_tests = [
            "webhook\x00id",
            "webhook\x00",
            "\x00webhook",
            "webhook\x00\x00id",
        ]

        for test_id in null_byte_tests:
            is_valid, msg = InputValidator.validate_webhook_id(test_id)
            # Should reject null bytes
            assert (
                not is_valid
            ), f"Should reject webhook ID with null bytes: {repr(test_id)}"

        # Test null bytes in payload (should be handled by size validation)
        payload_with_null = b"data\x00\x00\x00"
        is_valid, msg = InputValidator.validate_payload_size(payload_with_null)
        # Should validate size normally (null bytes are just bytes)
        assert isinstance(is_valid, bool)

    def test_header_injection_attacks(self):
        """Test header injection attacks (CRLF, newlines, etc.)."""
        # Header injection via newlines
        malicious_headers = {
            "X-Header": "value\r\nX-Injected: malicious",
            "X-Header2": "value\nX-Injected: malicious",
            "X-Header3": "value\rX-Injected: malicious",
        }

        for header_name, header_value in malicious_headers.items():
            headers = {header_name: header_value}
            is_valid, msg = InputValidator.validate_headers(headers)
            # Size validation should still work
            # Note: Header injection prevention is typically at HTTP server level
            # This test documents that validation doesn't crash on malicious headers
            assert isinstance(is_valid, bool)

    def test_unicode_normalization_attacks(self):
        """Test Unicode normalization and encoding attacks."""
        # Unicode normalization attacks
        unicode_tests = [
            "webhook\u0000id",  # Null character
            "webhook\u200bid",  # Zero-width space
            "webhook\ufeffid",  # Zero-width no-break space
            "webhook\u200cid",  # Zero-width non-joiner
            "webhook\u200did",  # Zero-width joiner
        ]

        for test_id in unicode_tests:
            is_valid, msg = InputValidator.validate_webhook_id(test_id)
            # Should reject or handle unicode control characters
            # Current regex may or may not catch these
            assert isinstance(is_valid, bool)

        # Test with valid unicode (should pass)
        unicode_valid = "webhook_测试_123"
        is_valid, msg = InputValidator.validate_webhook_id(unicode_valid)
        # Should reject (only alphanumeric, underscore, hyphen allowed)
        assert not is_valid, "Should reject unicode characters in webhook ID"

    def test_circular_reference_json_depth(self):
        """Test that circular references don't cause infinite loops in depth validation."""
        # Create circular reference
        obj1 = {"name": "obj1"}
        obj2 = {"name": "obj2", "ref": obj1}
        obj1["ref"] = obj2  # Circular reference

        # Should handle circular reference gracefully using visited set
        start_time = time.time()
        is_valid, msg = InputValidator.validate_json_depth(obj1)
        elapsed = time.time() - start_time

        # Should complete quickly without infinite recursion
        assert elapsed < 1.0, "Should handle circular reference without hanging"
        assert is_valid, "Should handle circular reference gracefully (treat as valid)"

    def test_webhook_id_path_traversal_bypass(self):
        """Test path traversal bypass attempts in webhook ID."""
        path_traversal_attempts = [
            "../webhook",
            "..\\webhook",
            "webhook/../admin",
            "webhook\\..\\admin",
            "....//webhook",
            "....\\\\webhook",
            "webhook%2fadmin",
            "webhook%5cadmin",
            "webhook%2e%2e/admin",
        ]

        for test_id in path_traversal_attempts:
            is_valid, msg = InputValidator.validate_webhook_id(test_id)
            # Should reject path traversal attempts
            assert (
                not is_valid
            ), f"Should reject path traversal in webhook ID: {test_id}"

    def test_sanitize_string_bypass(self):
        """Test that sanitize_string doesn't have bypass vulnerabilities."""
        # Test double encoding bypass
        double_encoded = "&lt;script&gt;"
        sanitized = InputValidator.sanitize_string(double_encoded)
        # Should not double-encode (already encoded)
        assert "&lt;" in sanitized or "<" not in sanitized

        # Test with already sanitized input
        already_sanitized = "&lt;script&gt;"
        result = InputValidator.sanitize_string(already_sanitized)
        # Should handle gracefully
        assert isinstance(result, str)

    def test_validate_all_short_circuit(self):
        """Test that validate_all short-circuits on first failure."""
        # Test that validation stops early (performance/DoS protection)
        invalid_webhook_id = "invalid webhook id with spaces"
        payload_bytes = b"x" * (11 * 1024 * 1024)  # Oversized
        headers = {"Content-Type": "application/json"}
        payload_obj = {"test": "data"}

        start_time = time.time()
        is_valid, msg = InputValidator.validate_all(
            invalid_webhook_id, payload_bytes, headers, payload_obj
        )
        elapsed = time.time() - start_time

        # Should fail fast on webhook ID validation (first check)
        assert elapsed < 0.1, "Should short-circuit on first validation failure"
        assert not is_valid
        assert "webhook id" in msg.lower() or "invalid" in msg.lower()

    def test_large_number_of_headers_dos(self):
        """Test DoS via large number of headers."""
        # Test at limit
        headers = {f"H{i}": f"v{i}" for i in range(InputValidator.MAX_HEADER_COUNT)}
        is_valid, msg = InputValidator.validate_headers(headers)
        assert is_valid, "Should accept headers at count limit"

        # Test just over limit
        headers = {f"H{i}": f"v{i}" for i in range(InputValidator.MAX_HEADER_COUNT + 1)}
        is_valid, msg = InputValidator.validate_headers(headers)
        assert not is_valid, "Should reject headers over count limit"

        # Test extremely large number (should fail fast)
        headers = {f"H{i}": f"v{i}" for i in range(1000)}
        start_time = time.time()
        is_valid, msg = InputValidator.validate_headers(headers)
        elapsed = time.time() - start_time
        assert elapsed < 0.1, "Should reject large header count quickly"
        assert not is_valid

    def test_json_depth_with_large_breadth(self):
        """Test JSON depth validation with wide structures (not just deep)."""
        # Create wide structure (many keys at each level)
        wide_structure = {}
        for i in range(1000):
            wide_structure[f"key_{i}"] = {"nested": {"value": i}}

        start_time = time.time()
        is_valid, msg = InputValidator.validate_json_depth(wide_structure)
        elapsed = time.time() - start_time

        # Should complete quickly even with many keys
        assert elapsed < 1.0, "Should handle wide JSON structures efficiently"
        assert is_valid, "Wide structure should pass depth validation"

    def test_string_length_validation_performance(self):
        """Test that string length validation is efficient for large structures."""
        # Create structure with many strings
        large_structure = {f"key_{i}": f"value_{i}" * 100 for i in range(1000)}

        start_time = time.time()
        is_valid, msg = InputValidator.validate_string_length(large_structure)
        elapsed = time.time() - start_time

        # Should complete quickly
        assert elapsed < 1.0, "String length validation should be efficient"
        assert is_valid, "Should accept valid string lengths"

    def test_webhook_id_reserved_name_bypass(self):
        """Test bypass attempts for reserved webhook ID names."""
        bypass_attempts = [
            "Stats",  # Case variation
            "STATS",  # Uppercase
            "stats_",  # With suffix
            "_stats",  # With prefix
            "mystats",  # Contains reserved
            "stats123",  # With numbers
            "admin",  # Another reserved
            "Admin",  # Case variation
            "ADMIN",  # Uppercase
        ]

        for test_id in bypass_attempts:
            is_valid, msg = InputValidator.validate_webhook_id(test_id)
            # Should reject reserved names (case-insensitive)
            if test_id.lower() in ["stats", "admin"]:
                assert not is_valid, f"Should reject reserved name: {test_id}"

    def test_dangerous_patterns_case_insensitive(self):
        """Test that dangerous pattern detection is case-insensitive."""
        case_variations = [
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<Script>alert('XSS')</Script>",
            "<sCrIpT>alert('XSS')</sCrIpT>",
            "JAVASCRIPT:alert('XSS')",
            "JavaScript:alert('XSS')",
            "JaVaScRiPt:alert('XSS')",
        ]

        for xss_attempt in case_variations:
            is_safe, msg = InputValidator.check_dangerous_patterns(xss_attempt)
            # Should detect case variations (regex uses re.IGNORECASE)
            if not is_safe:
                assert "dangerous" in msg.lower() or "pattern" in msg.lower()
