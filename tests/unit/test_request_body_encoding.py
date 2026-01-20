"""
Security tests for request body encoding handling.
Tests that request bodies are properly decoded with encoding detection and fallback.
"""

import pytest
from fastapi import HTTPException
from src.utils import safe_decode_body, detect_encoding_from_content_type


class TestRequestBodyEncoding:
    """Test suite for request body encoding handling."""

    def test_detect_encoding_from_content_type(self):
        """Test encoding detection from Content-Type header."""
        # UTF-8 encoding
        assert (
            detect_encoding_from_content_type("application/json; charset=utf-8")
            == "utf-8"
        )
        assert (
            detect_encoding_from_content_type("application/json; charset=UTF-8")
            == "utf-8"
        )
        assert (
            detect_encoding_from_content_type("application/json; charset='utf-8'")
            == "utf-8"
        )
        assert (
            detect_encoding_from_content_type('application/json; charset="utf-8"')
            == "utf-8"
        )

        # Other encodings
        assert (
            detect_encoding_from_content_type("text/plain; charset=iso-8859-1")
            == "iso-8859-1"
        )
        assert (
            detect_encoding_from_content_type("application/json; charset=latin-1")
            == "latin-1"
        )
        assert (
            detect_encoding_from_content_type("application/json; charset=utf-16")
            == "utf-16"
        )

        # No charset
        assert detect_encoding_from_content_type("application/json") is None
        assert detect_encoding_from_content_type("text/plain") is None

        # None or empty
        assert detect_encoding_from_content_type(None) is None
        assert detect_encoding_from_content_type("") is None

    def test_safe_decode_body_utf8(self):
        """Test decoding UTF-8 body."""
        body = "Hello, 世界!".encode("utf-8")
        decoded, encoding = safe_decode_body(body)
        assert decoded == "Hello, 世界!"
        assert encoding == "utf-8"

    def test_safe_decode_body_utf8_with_content_type(self):
        """Test decoding UTF-8 body with Content-Type header."""
        body = "Hello, 世界!".encode("utf-8")
        content_type = "application/json; charset=utf-8"
        decoded, encoding = safe_decode_body(body, content_type)
        assert decoded == "Hello, 世界!"
        assert encoding == "utf-8"

    def test_safe_decode_body_latin1(self):
        """Test decoding Latin-1 body."""
        # Latin-1 can encode any byte value
        body = b"\x80\x81\x82"
        decoded, encoding = safe_decode_body(body)
        # Should fallback to latin-1 if UTF-8 fails
        assert encoding in ["latin-1", "iso-8859-1"]
        assert len(decoded) == 3

    def test_safe_decode_body_latin1_with_content_type(self):
        """Test decoding Latin-1 body with Content-Type header."""
        body = b"\x80\x81\x82"
        content_type = "application/json; charset=iso-8859-1"
        decoded, encoding = safe_decode_body(body, content_type)
        assert encoding == "iso-8859-1"
        assert len(decoded) == 3

    def test_safe_decode_body_utf16(self):
        """Test decoding UTF-16 body."""
        body = "Hello".encode("utf-16le")
        content_type = "application/json; charset=utf-16le"
        decoded, encoding = safe_decode_body(body, content_type)
        assert decoded == "Hello"
        assert encoding == "utf-16le"

    def test_safe_decode_body_invalid_encoding_in_header(self):
        """Test handling of invalid encoding in Content-Type header."""
        body = "Hello".encode("utf-8")
        content_type = "application/json; charset=invalid-encoding"
        # Should fallback to UTF-8
        decoded, encoding = safe_decode_body(body, content_type)
        assert decoded == "Hello"
        assert encoding == "utf-8"

    def test_safe_decode_body_fallback_encodings(self):
        """Test that fallback encodings work."""
        # Create body that's not valid UTF-8
        # Use bytes that are definitely invalid UTF-8 but valid in latin-1
        body = b"\x80\x81\x82\xff"  # Invalid UTF-8 sequences (but valid in latin-1)
        # Should try UTF-8, fail, then try other encodings
        decoded, encoding = safe_decode_body(body)
        # Any encoding from the fallback list should work
        # The important thing is that decoding succeeds without raising an exception
        assert encoding in [
            "latin-1",
            "iso-8859-1",
            "cp1252",
            "utf-8",
            "utf-16",
            "utf-16le",
            "utf-16be",
        ]
        # Verify decoding succeeded
        assert isinstance(decoded, str)
        # Verify we got some decoded content
        assert len(decoded) > 0

    def test_safe_decode_body_empty(self):
        """Test decoding empty body."""
        body = b""
        decoded, encoding = safe_decode_body(body)
        assert decoded == ""
        assert encoding == "utf-8"

    def test_safe_decode_body_unicode_characters(self):
        """Test decoding body with Unicode characters."""
        # Various Unicode characters
        test_strings = [
            "Hello, 世界!",
            "Привет",
            "こんにちは",
            "مرحبا",
            "🌍🌎🌏",
        ]

        for test_str in test_strings:
            body = test_str.encode("utf-8")
            decoded, encoding = safe_decode_body(body)
            assert decoded == test_str
            assert encoding == "utf-8"

    def test_safe_decode_body_json_content(self):
        """Test decoding JSON content."""
        json_str = '{"key": "value", "number": 123}'
        body = json_str.encode("utf-8")
        content_type = "application/json; charset=utf-8"
        decoded, encoding = safe_decode_body(body, content_type)
        assert decoded == json_str
        assert encoding == "utf-8"

    def test_safe_decode_body_encoding_precedence(self):
        """Test that Content-Type encoding takes precedence."""
        # Body is valid UTF-8, but Content-Type says latin-1
        body = "Hello".encode("utf-8")
        content_type = "application/json; charset=latin-1"
        # Should use latin-1 from header (even though UTF-8 would work)
        decoded, encoding = safe_decode_body(body, content_type)
        assert encoding == "latin-1"
        # Both should decode the same for ASCII characters
        assert decoded == "Hello"

    def test_safe_decode_body_error_handling(self):
        """Test error handling for body with various byte values."""
        # Create body with various byte values
        # UTF-8 can decode some, but not all byte sequences
        body = b"\x00\x01\x02\x80\xff"
        # Should succeed with one of the encodings
        decoded, encoding = safe_decode_body(body)
        # Any encoding should work (latin-1 can decode any byte)
        assert encoding in ["latin-1", "iso-8859-1", "cp1252", "utf-8"]
        # If UTF-8, might have replacement chars, otherwise should match length
        if encoding == "utf-8":
            # UTF-8 with errors='replace' might add replacement chars
            assert len(decoded) >= len(body) - 2  # Some bytes might be replaced
        else:
            assert len(decoded) == len(body)

    def test_safe_decode_body_case_insensitive_charset(self):
        """Test that charset detection is case-insensitive."""
        body = "Hello".encode("utf-8")
        content_types = [
            "application/json; charset=UTF-8",
            "application/json; charset=Utf-8",
            "application/json; charset=uTf-8",
        ]

        for content_type in content_types:
            decoded, encoding = safe_decode_body(body, content_type)
            assert encoding == "utf-8"
            assert decoded == "Hello"

    def test_safe_decode_body_multiple_charsets(self):
        """Test handling of multiple charset declarations (should use first)."""
        # This is an edge case - Content-Type shouldn't have multiple charsets
        body = "Hello".encode("utf-8")
        content_type = "application/json; charset=utf-8; charset=latin-1"
        decoded, encoding = safe_decode_body(body, content_type)
        # Should use first charset
        assert encoding == "utf-8"

    def test_safe_decode_body_whitespace_in_charset(self):
        """Test handling of whitespace in charset declaration."""
        body = "Hello".encode("utf-8")
        content_types = [
            "application/json; charset= utf-8",
            "application/json; charset =utf-8",
            "application/json; charset = utf-8",
            "application/json; charset='utf-8'",
            'application/json; charset="utf-8"',
        ]

        for content_type in content_types:
            decoded, encoding = safe_decode_body(body, content_type)
            assert encoding == "utf-8"
            assert decoded == "Hello"
