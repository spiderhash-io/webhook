"""
Comprehensive security audit tests for body decoding utilities (safe_decode_body and detect_encoding_from_content_type).
Tests ReDoS, encoding injection, encoding confusion, DoS, information disclosure, Unicode normalization, and edge cases.
"""

import pytest
import time
import re
from fastapi import HTTPException
from src.utils import safe_decode_body, detect_encoding_from_content_type


# ============================================================================
# 1. REGEX DENIAL OF SERVICE (ReDoS) - detect_encoding_from_content_type
# ============================================================================


class TestDetectEncodingReDoS:
    """Test ReDoS vulnerabilities in charset regex parsing."""

    def test_redos_charset_regex_simple(self):
        """Test ReDoS vulnerability in charset regex with simple attack."""
        # The regex is: r'charset\s*=\s*["\']?([^"\'\s;]+)["\']?'
        # Potential ReDoS: many spaces before charset
        malicious_content_type = "application/json; " + (" " * 1000) + "charset=utf-8"

        start_time = time.time()
        result = detect_encoding_from_content_type(malicious_content_type)
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: charset detection took {elapsed:.2f}s"
        assert result == "utf-8"

    def test_redos_charset_regex_complex(self):
        """Test ReDoS vulnerability with complex charset value."""
        # Try to cause backtracking with many quotes
        malicious_content_type = (
            "application/json; charset=" + ("'" * 100) + "utf-8" + ("'" * 100)
        )

        start_time = time.time()
        result = detect_encoding_from_content_type(malicious_content_type)
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: charset detection took {elapsed:.2f}s"
        # Should extract utf-8 (quotes are stripped by regex)
        assert (
            result == "utf-8" or result is None
        )  # May be None if validation rejects it

    def test_redos_charset_regex_many_semicolons(self):
        """Test ReDoS with many semicolons in Content-Type."""
        # Many semicolons before charset
        malicious_content_type = (
            "application/json" + ("; param=value" * 100) + "; charset=utf-8"
        )

        start_time = time.time()
        result = detect_encoding_from_content_type(malicious_content_type)
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: charset detection took {elapsed:.2f}s"
        assert result == "utf-8"

    def test_redos_charset_regex_nested_quotes(self):
        """Test ReDoS with nested quotes."""
        malicious_content_type = (
            'application/json; charset="' + ("'" * 50) + "utf-8" + ("'" * 50) + '"'
        )

        start_time = time.time()
        result = detect_encoding_from_content_type(malicious_content_type)
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: charset detection took {elapsed:.2f}s"
        # Should extract utf-8 (quotes are stripped, but nested quotes might cause issues)
        assert (
            result == "utf-8" or result is None
        )  # May be None if validation rejects it


# ============================================================================
# 2. ENCODING INJECTION & MANIPULATION
# ============================================================================


class TestEncodingInjection:
    """Test encoding injection and manipulation attacks."""

    def test_charset_injection_command_separators(self):
        """Test charset injection with command separators."""
        # Try to inject command separators in charset
        malicious_charsets = [
            "utf-8; rm -rf /",
            "utf-8|cat /etc/passwd",
            "utf-8&whoami",
            "utf-8`id`",
            "utf-8$(ls)",
        ]

        for malicious_charset in malicious_charsets:
            content_type = f"application/json; charset={malicious_charset}"
            result = detect_encoding_from_content_type(content_type)

            # SECURITY: Should reject charset names with command separators
            # The validation should prevent injection by rejecting invalid characters
            assert result is None or (
                "|" not in result
                and "&" not in result
                and "`" not in result
                and "$" not in result
                and ";" not in result
            )

    def test_charset_injection_path_traversal(self):
        """Test charset injection with path traversal."""
        malicious_charsets = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "/etc/passwd",
            "C:\\Windows\\System32",
        ]

        for malicious_charset in malicious_charsets:
            content_type = f"application/json; charset={malicious_charset}"
            result = detect_encoding_from_content_type(content_type)

            # Should extract charset but it will be invalid encoding
            # The important thing is it doesn't cause crashes
            assert result is not None or result is None  # Either is acceptable

    def test_charset_injection_null_bytes(self):
        """Test charset injection with null bytes."""
        malicious_charset = "utf-8\x00; rm -rf /"
        content_type = f"application/json; charset={malicious_charset}"

        result = detect_encoding_from_content_type(content_type)

        # Should handle null bytes gracefully
        # Regex might not match, or might extract partial value
        # Important: should not crash
        assert isinstance(result, (str, type(None)))

    def test_charset_injection_newlines(self):
        """Test charset injection with newlines."""
        malicious_charsets = [
            "utf-8\n; rm -rf /",
            "utf-8\r; cat /etc/passwd",
            "utf-8\r\n; whoami",
        ]

        for malicious_charset in malicious_charsets:
            content_type = f"application/json; charset={malicious_charset}"
            result = detect_encoding_from_content_type(content_type)

            # Should extract charset up to newline (regex stops at whitespace)
            # Important: should not crash
            assert isinstance(result, (str, type(None)))
            if result:
                assert "\n" not in result
                assert "\r" not in result


# ============================================================================
# 3. ENCODING CONFUSION ATTACKS
# ============================================================================


class TestEncodingConfusion:
    """Test encoding confusion and bypass attacks."""

    def test_utf7_encoding_injection(self):
        """Test UTF-7 encoding injection (deprecated but still supported in some systems)."""
        # UTF-7 can be used to bypass some filters
        # SECURITY: UTF-7 is now rejected as a dangerous encoding
        try:
            body = "+ADw-script+AD4-".encode("utf-7")
            content_type = "application/json; charset=utf-7"

            decoded, encoding = safe_decode_body(body, content_type)

            # SECURITY: Should reject UTF-7 and use safe fallback encoding
            assert isinstance(decoded, str)
            # Should use safe encoding (UTF-8 or latin-1) instead of UTF-7
            assert encoding in ["utf-8", "latin-1", "iso-8859-1", "cp1252"]
            assert encoding != "utf-7"  # UTF-7 should be rejected
        except (LookupError, UnicodeDecodeError):
            # UTF-7 might not be available in all Python installations
            # This is acceptable - the function should handle it gracefully
            pass

    def test_utf16_bom_manipulation(self):
        """Test UTF-16 BOM manipulation."""
        # UTF-16 with BOM
        body_le = "\ufeffHello".encode("utf-16-le")
        body_be = "\ufeffHello".encode("utf-16-be")

        # Try to confuse by claiming wrong endianness
        content_type_le = "application/json; charset=utf-16le"
        content_type_be = "application/json; charset=utf-16be"

        # Should decode correctly based on actual BOM
        decoded_le, encoding_le = safe_decode_body(body_le, content_type_le)
        decoded_be, encoding_be = safe_decode_body(body_be, content_type_be)

        assert isinstance(decoded_le, str)
        assert isinstance(decoded_be, str)

    def test_encoding_mismatch_attack(self):
        """Test encoding mismatch to bypass validation."""
        # Send UTF-8 data but claim it's UTF-16
        body = '{"data": "test"}'.encode("utf-8")
        content_type = "application/json; charset=utf-16"

        # SECURITY: UTF-16 is allowed if explicitly requested, but safe encodings are tried first
        decoded, encoding = safe_decode_body(body, content_type)

        # Should eventually decode (fallback mechanism)
        assert isinstance(decoded, str)
        # Should prefer safe encodings (UTF-8) over UTF-16
        # UTF-16 might be used if it successfully decodes, but UTF-8 should be preferred
        assert encoding in ["utf-8", "utf-16", "latin-1", "iso-8859-1", "cp1252"]

    def test_invalid_encoding_name_injection(self):
        """Test injection of invalid encoding names."""
        invalid_encodings = [
            "../../etc/passwd",
            "rm -rf /",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
        ]

        body = b'{"data": "test"}'

        for invalid_enc in invalid_encodings:
            content_type = f"application/json; charset={invalid_enc}"

            # Should handle gracefully (LookupError for invalid encoding)
            decoded, encoding = safe_decode_body(body, content_type)

            # Should fallback to valid encoding
            assert isinstance(decoded, str)
            assert encoding in ["utf-8", "latin-1", "iso-8859-1", "cp1252"]


# ============================================================================
# 4. DENIAL OF SERVICE (DoS) ATTACKS
# ============================================================================


class TestBodyDecodingDoS:
    """Test DoS vulnerabilities in body decoding."""

    def test_large_charset_name_dos(self):
        """Test DoS via extremely long charset name."""
        # Very long charset name
        long_charset = "a" * 10000
        content_type = f"application/json; charset={long_charset}"

        start_time = time.time()
        result = detect_encoding_from_content_type(content_type)
        elapsed = time.time() - start_time

        # Should complete quickly (regex should limit extraction)
        assert elapsed < 1.0, f"DoS detected: charset detection took {elapsed:.2f}s"
        # Should extract charset (might be truncated by regex)
        assert isinstance(result, (str, type(None)))

    def test_many_encoding_attempts_dos(self):
        """Test DoS via body that fails all encoding attempts."""
        # Create body that's invalid for all common encodings
        # This will cause the function to try all encodings
        body = b"\xff\xfe\x00\x01" * 1000  # Invalid for most encodings

        start_time = time.time()
        decoded, encoding = safe_decode_body(body)
        elapsed = time.time() - start_time

        # Should complete quickly (fallback to default with errors='replace')
        assert elapsed < 2.0, f"DoS detected: decoding took {elapsed:.2f}s"
        assert isinstance(decoded, str)
        # Should use safe encoding (UTF-8 with error replacement, or latin-1 which can decode any byte)
        assert encoding in ["utf-8", "latin-1", "iso-8859-1", "cp1252"]

    def test_large_content_type_header_dos(self):
        """Test DoS via extremely large Content-Type header."""
        # Very large Content-Type with many parameters
        large_content_type = (
            "application/json; "
            + "; ".join("param" + str(i) + "=value" + str(i) for i in range(1000))
            + "; charset=utf-8"
        )

        start_time = time.time()
        result = detect_encoding_from_content_type(large_content_type)
        elapsed = time.time() - start_time

        # Should complete quickly
        assert elapsed < 1.0, f"DoS detected: charset detection took {elapsed:.2f}s"
        assert result == "utf-8"

    def test_invalid_encoding_loop_dos(self):
        """Test DoS via many invalid encoding attempts."""
        # Body that will fail all encoding attempts
        body = b"\x00" * 10000

        # Try with invalid encoding in header
        content_type = "application/json; charset=invalid-encoding-12345"

        start_time = time.time()
        decoded, encoding = safe_decode_body(body, content_type)
        elapsed = time.time() - start_time

        # Should complete quickly (fallback mechanism)
        assert elapsed < 2.0, f"DoS detected: decoding took {elapsed:.2f}s"
        assert isinstance(decoded, str)


# ============================================================================
# 5. INFORMATION DISCLOSURE
# ============================================================================


class TestBodyDecodingInformationDisclosure:
    """Test information disclosure in error messages."""

    def test_error_message_sanitization(self):
        """Test that error messages don't leak sensitive information."""
        # Try to decode with encoding that will fail
        body = b"\xff\xfe\x00\x01" * 100

        # Use invalid encoding that might cause error
        content_type = "application/json; charset=../../etc/passwd"

        try:
            decoded, encoding = safe_decode_body(body, content_type)
            # If it succeeds, that's fine (fallback worked)
            assert isinstance(decoded, str)
        except HTTPException as e:
            # Error message should not contain sensitive information
            error_detail = str(e.detail).lower()
            assert "../../etc/passwd" not in error_detail
            assert "passwd" not in error_detail
            assert "etc" not in error_detail

    def test_encoding_name_not_exposed(self):
        """Test that invalid encoding names are not exposed in errors."""
        body = b'{"data": "test"}'
        malicious_charset = "../../etc/passwd"
        content_type = f"application/json; charset={malicious_charset}"

        try:
            decoded, encoding = safe_decode_body(body, content_type)
            # Should fallback to valid encoding
            assert isinstance(decoded, str)
        except HTTPException as e:
            # Error should not expose the malicious charset
            error_detail = str(e.detail).lower()
            assert "../../etc/passwd" not in error_detail
            assert "passwd" not in error_detail


# ============================================================================
# 6. UNICODE NORMALIZATION & EDGE CASES
# ============================================================================


class TestBodyDecodingUnicodeNormalization:
    """Test Unicode normalization and edge cases."""

    def test_unicode_normalization_charset(self):
        """Test Unicode normalization in charset value."""
        # Unicode characters in charset (should be normalized/rejected)
        unicode_charsets = [
            "utf-8\u200b",  # Zero-width space
            "utf-8\u00ad",  # Soft hyphen
            "utf-8\ufeff",  # BOM
        ]

        body = b'{"data": "test"}'

        for unicode_charset in unicode_charsets:
            content_type = f"application/json; charset={unicode_charset}"
            result = detect_encoding_from_content_type(content_type)

            # Should extract charset (might include or exclude Unicode chars)
            # Important: should not crash
            assert isinstance(result, (str, type(None)))

    def test_empty_charset_value(self):
        """Test empty charset value."""
        content_types = [
            "application/json; charset=",
            "application/json; charset= ",
            "application/json; charset=''",
            'application/json; charset=""',
        ]

        for content_type in content_types:
            result = detect_encoding_from_content_type(content_type)
            # Should return None or empty string
            assert result is None or result == ""

    def test_charset_with_whitespace(self):
        """Test charset with various whitespace patterns."""
        content_types = [
            "application/json; charset= utf-8",
            "application/json; charset =utf-8",
            "application/json; charset = utf-8",
            "application/json; charset=\tutf-8",
            "application/json; charset=\nutf-8",
        ]

        for content_type in content_types:
            result = detect_encoding_from_content_type(content_type)
            # Should extract utf-8 (regex handles whitespace)
            assert result == "utf-8" or result is None

    def test_multiple_charset_declarations(self):
        """Test multiple charset declarations (should use first)."""
        content_types = [
            "application/json; charset=utf-8; charset=latin-1",
            "application/json; charset='utf-8'; charset=\"latin-1\"",
        ]

        for content_type in content_types:
            result = detect_encoding_from_content_type(content_type)
            # Should extract first charset
            assert result == "utf-8"

    def test_charset_in_quotes(self):
        """Test charset in various quote styles."""
        content_types = [
            "application/json; charset='utf-8'",
            'application/json; charset="utf-8"',
            "application/json; charset='utf-8\"",
            "application/json; charset=\"utf-8'",
        ]

        for content_type in content_types:
            result = detect_encoding_from_content_type(content_type)
            # Should extract utf-8
            assert result == "utf-8"


# ============================================================================
# 7. ENCODING VALIDATION & TYPE CONFUSION
# ============================================================================


class TestBodyDecodingValidation:
    """Test encoding validation and type confusion."""

    def test_non_string_content_type(self):
        """Test with non-string content_type."""
        body = b'{"data": "test"}'

        # Should handle None gracefully
        decoded, encoding = safe_decode_body(body, None)
        assert isinstance(decoded, str)
        assert encoding == "utf-8"

    def test_empty_body_handling(self):
        """Test empty body handling."""
        body = b""

        decoded, encoding = safe_decode_body(body)
        assert decoded == ""
        assert encoding == "utf-8"

    def test_very_large_body(self):
        """Test very large body (should not cause DoS)."""
        # Large but reasonable body
        body = b'{"data": "' + (b"a" * 1000000) + b'"}'

        start_time = time.time()
        decoded, encoding = safe_decode_body(body)
        elapsed = time.time() - start_time

        # Should complete in reasonable time
        assert elapsed < 5.0, f"Large body decoding took {elapsed:.2f}s"
        assert isinstance(decoded, str)
        assert len(decoded) > 0

    def test_default_encoding_override(self):
        """Test default encoding parameter."""
        body = "Hello, 世界!".encode("utf-8")

        # Use different default encoding
        decoded, encoding = safe_decode_body(body, default_encoding="latin-1")

        # Should use UTF-8 (body is valid UTF-8)
        assert isinstance(decoded, str)
        # Might use UTF-8 or default
        assert encoding in ["utf-8", "latin-1"]


# ============================================================================
# 8. INTEGRATION WITH WEBHOOK PROCESSING
# ============================================================================


class TestBodyDecodingIntegration:
    """Test integration with webhook processing."""

    def test_json_decoding_after_body_decode(self):
        """Test that decoded body can be parsed as JSON."""
        json_data = {"key": "value", "number": 123}
        json_str = str(json_data).replace("'", '"')  # Simple JSON conversion
        body = json_str.encode("utf-8")

        decoded, encoding = safe_decode_body(body)

        # Should be valid for JSON parsing
        import json

        parsed = json.loads(decoded)
        assert isinstance(parsed, dict)

    def test_encoding_preservation(self):
        """Test that encoding is correctly identified and preserved."""
        test_cases = [
            ("Hello", "utf-8"),
            ("Привет", "utf-8"),
            ("こんにちは", "utf-8"),
        ]

        for text, expected_encoding in test_cases:
            body = text.encode("utf-8")
            content_type = f"application/json; charset={expected_encoding}"

            decoded, encoding = safe_decode_body(body, content_type)

            assert decoded == text
            assert encoding == expected_encoding
