"""
Security tests for CORS configuration.
Tests that CORS is properly restricted to prevent CSRF and unauthorized access.
"""

import pytest
import os
from unittest.mock import patch
from fastapi.testclient import TestClient


def _validate_cors_origin(origin: str) -> bool:
    """
    Validate CORS origin using the same logic as main.py.
    This is extracted for testing purposes.
    """
    # Explicitly reject wildcard for security
    if origin == "*" or origin == "null":
        return False

    # Validate origin format (must be http:// or https:// with valid domain)
    if not (origin.startswith("http://") or origin.startswith("https://")):
        return False

    # Basic validation: must have domain after protocol
    domain_part = origin.split("://", 1)[1] if "://" in origin else ""
    if not domain_part or domain_part.startswith("/") or " " in domain_part:
        return False

    # Reject origins with paths, fragments, query strings, or userinfo (security: prevent subdomain confusion)
    # Origin should only be protocol + domain + optional port
    if (
        "/" in domain_part
        or "#" in domain_part
        or "?" in domain_part
        or "@" in domain_part
    ):
        # Extract just the domain:port part (before any /, #, ?, @)
        domain_only = (
            domain_part.split("/")[0].split("#")[0].split("?")[0].split("@")[0]
        )
        # If the domain part is different from what we extracted, reject it
        if domain_part != domain_only:
            return False

    return True


def _parse_cors_origins(env_value: str) -> list:
    """
    Parse CORS origins from environment variable using the same logic as main.py.
    """
    cors_allowed_origins = []

    if not env_value or not env_value.strip():
        return cors_allowed_origins

    raw_origins = [origin.strip() for origin in env_value.split(",") if origin.strip()]

    for origin in raw_origins:
        if _validate_cors_origin(origin):
            cors_allowed_origins.append(origin)

    return cors_allowed_origins


class TestCORSSecurity:
    """Test suite for CORS security configuration."""

    def test_cors_wildcard_rejected(self):
        """Test that wildcard '*' origin is rejected."""
        origins = _parse_cors_origins("*")
        assert "*" not in origins
        assert len(origins) == 0

    def test_cors_null_origin_rejected(self):
        """Test that 'null' origin is rejected."""
        origins = _parse_cors_origins("null")
        assert "null" not in origins
        assert len(origins) == 0

    def test_cors_invalid_origin_format_rejected(self):
        """Test that invalid origin formats are rejected."""
        invalid_origins = [
            "example.com",  # Missing protocol
            "ftp://example.com",  # Invalid protocol
            "http://",  # No domain
            "https:// /path",  # Space in origin
        ]

        for invalid_origin in invalid_origins:
            origins = _parse_cors_origins(invalid_origin)
            assert invalid_origin not in origins
            assert len(origins) == 0

    def test_cors_valid_origins_accepted(self):
        """Test that valid origins are accepted."""
        valid_origins = [
            "https://example.com",
            "https://app.example.com",
            "http://localhost:3000",  # Allowed but warned
        ]

        for valid_origin in valid_origins:
            origins = _parse_cors_origins(valid_origin)
            assert valid_origin in origins
            assert len(origins) == 1

    def test_cors_multiple_valid_origins(self):
        """Test that multiple valid origins are accepted."""
        origins_str = (
            "https://example.com,https://app.example.com,https://api.example.com"
        )
        origins = _parse_cors_origins(origins_str)

        assert "https://example.com" in origins
        assert "https://app.example.com" in origins
        assert "https://api.example.com" in origins
        assert len(origins) == 3

    def test_cors_mixed_valid_invalid_origins(self):
        """Test that invalid origins are filtered out from mixed list."""
        origins_str = "https://example.com,*,https://app.example.com,null,invalid"
        origins = _parse_cors_origins(origins_str)

        # Valid origins should be included
        assert "https://example.com" in origins
        assert "https://app.example.com" in origins

        # Invalid origins should be filtered out
        assert "*" not in origins
        assert "null" not in origins
        assert "invalid" not in origins
        assert len(origins) == 2

    def test_cors_no_origins_default_secure(self):
        """Test that default (no CORS env var) is secure (no CORS allowed)."""
        origins = _parse_cors_origins("")
        assert len(origins) == 0

        origins = _parse_cors_origins("   ")
        assert len(origins) == 0

    def test_cors_origin_validation_strict(self):
        """Test that origin validation is strict and rejects paths/fragments/queries."""
        # Test various malicious origin attempts
        malicious_origins = [
            "https://example.com@evil.com",  # User info injection
            "https://example.com/evil",  # Path injection
            "https://example.com#evil",  # Fragment injection
            "https://example.com?evil=1",  # Query injection
            "https://example.com:443/evil",  # Path with port
        ]

        for malicious_origin in malicious_origins:
            # These should be rejected by our enhanced validation
            is_valid = _validate_cors_origin(malicious_origin)
            # Path, fragment, query, and userinfo should be rejected
            assert is_valid is False, f"Origin '{malicious_origin}' should be rejected"

        # Valid origins (no path/fragment/query)
        valid_origins = [
            "https://example.com",
            "https://example.com:443",
            "http://localhost:3000",
        ]

        for valid_origin in valid_origins:
            is_valid = _validate_cors_origin(valid_origin)
            assert is_valid is True, f"Origin '{valid_origin}' should be accepted"

    def test_cors_whitespace_handling(self):
        """Test that whitespace in origins is handled correctly."""
        origins_str = "  https://example.com  ,  https://app.example.com  "
        origins = _parse_cors_origins(origins_str)

        assert "https://example.com" in origins
        assert "https://app.example.com" in origins
        assert len(origins) == 2

    def test_cors_empty_string_handling(self):
        """Test that empty strings in comma-separated list are ignored."""
        origins_str = "https://example.com,,https://app.example.com,"
        origins = _parse_cors_origins(origins_str)

        assert "https://example.com" in origins
        assert "https://app.example.com" in origins
        assert len(origins) == 2

    def test_cors_protocol_validation(self):
        """Test that only http:// and https:// protocols are allowed."""
        valid_protocols = ["https://example.com", "http://example.com"]
        invalid_protocols = [
            "ftp://example.com",
            "file://example.com",
            "ws://example.com",
            "wss://example.com",
        ]

        for origin in valid_protocols:
            assert _validate_cors_origin(origin) is True

        for origin in invalid_protocols:
            assert _validate_cors_origin(origin) is False
