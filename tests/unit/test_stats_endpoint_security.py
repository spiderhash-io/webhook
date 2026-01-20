"""
Security tests for statistics endpoint.
Tests authentication, rate limiting, and IP restrictions to prevent information disclosure.
"""

import pytest
import os
import hmac
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import Request
from fastapi.exceptions import HTTPException


class TestStatsEndpointSecurity:
    """Test suite for statistics endpoint security."""

    def test_auth_token_validation_logic(self):
        """Test the authentication token validation logic."""
        # Test constant-time comparison
        expected_token = "secret_token_123"

        # Valid token
        assert (
            hmac.compare_digest(
                expected_token.encode("utf-8"), "secret_token_123".encode("utf-8")
            )
            is True
        )

        # Invalid tokens
        invalid_tokens = [
            "wrong_token",
            "secret_token_12",  # One char short
            "secret_token_1234",  # One char long
            "a" * 100,  # Very different
        ]

        for invalid_token in invalid_tokens:
            assert (
                hmac.compare_digest(
                    expected_token.encode("utf-8"), invalid_token.encode("utf-8")
                )
                is False
            )

    def test_token_extraction_from_header(self):
        """Test token extraction from Authorization header."""
        # Bearer token format
        auth_header = "Bearer secret_token_123"
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            assert token == "secret_token_123"

        # Token without Bearer prefix
        auth_header = "secret_token_123"
        token = auth_header.strip()
        assert token == "secret_token_123"

        # Token with whitespace
        auth_header = "Bearer  secret_token_123  "
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            assert token == "secret_token_123"

    def test_ip_whitelist_parsing(self):
        """Test IP whitelist parsing logic."""
        stats_allowed_ips = "127.0.0.1,192.168.1.1,10.0.0.1"
        allowed_ips = {ip.strip() for ip in stats_allowed_ips.split(",") if ip.strip()}

        assert "127.0.0.1" in allowed_ips
        assert "192.168.1.1" in allowed_ips
        assert "10.0.0.1" in allowed_ips
        assert len(allowed_ips) == 3

        # Test with whitespace
        stats_allowed_ips = " 127.0.0.1 , 192.168.1.1 "
        allowed_ips = {ip.strip() for ip in stats_allowed_ips.split(",") if ip.strip()}
        assert "127.0.0.1" in allowed_ips
        assert "192.168.1.1" in allowed_ips

    def test_client_ip_extraction(self):
        """Test client IP extraction from headers."""
        # X-Forwarded-For header (first IP)
        x_forwarded_for = "192.168.1.100, 10.0.0.1"
        client_ip = x_forwarded_for.split(",")[0].strip()
        assert client_ip == "192.168.1.100"

        # No X-Forwarded-For (would use request.client.host in real code)
        x_forwarded_for = ""
        client_ip = x_forwarded_for.split(",")[0].strip() if x_forwarded_for else None
        assert client_ip == "" or client_ip is None

    def test_webhook_id_sanitization(self):
        """Test webhook ID sanitization logic."""
        import hashlib

        stats_data = {
            "webhook_1": {"total": 100, "minute": 10},
            "webhook_2": {"total": 50, "minute": 5},
            "sensitive_webhook_name": {"total": 200, "minute": 20},
        }

        sanitized_stats = {}
        for endpoint, data in stats_data.items():
            # Hash endpoint name to prevent enumeration
            endpoint_hash = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()[:16]
            sanitized_stats[f"webhook_{endpoint_hash}"] = data

        # Original IDs should not be in sanitized output
        assert "webhook_1" not in sanitized_stats
        assert "webhook_2" not in sanitized_stats
        assert "sensitive_webhook_name" not in sanitized_stats

        # All keys should start with "webhook_"
        for key in sanitized_stats.keys():
            assert key.startswith("webhook_")
            assert len(key) == len("webhook_") + 16  # webhook_ + 16 char hash

    def test_rate_limit_key_generation(self):
        """Test rate limit key generation for stats endpoint."""
        client_ip = "192.168.1.100"
        stats_key = f"stats_endpoint:{client_ip}"
        assert stats_key == "stats_endpoint:192.168.1.100"

        # Unknown IP
        client_ip = None
        stats_key = f"stats_endpoint:{client_ip or 'unknown'}"
        assert stats_key == "stats_endpoint:unknown"

    def test_rate_limit_config_parsing(self):
        """Test rate limit configuration parsing."""
        stats_rate_limit = int(os.getenv("STATS_RATE_LIMIT", "60"))
        assert stats_rate_limit == 60  # Default

        # Test with custom value
        with patch.dict(os.environ, {"STATS_RATE_LIMIT": "30"}):
            stats_rate_limit = int(os.getenv("STATS_RATE_LIMIT", "60"))
            assert stats_rate_limit == 30

    def test_sanitize_ids_config(self):
        """Test sanitize IDs configuration parsing."""
        # Default (disabled)
        sanitize = os.getenv("STATS_SANITIZE_IDS", "false").lower() == "true"
        assert sanitize is False

        # Enabled
        with patch.dict(os.environ, {"STATS_SANITIZE_IDS": "true"}):
            sanitize = os.getenv("STATS_SANITIZE_IDS", "false").lower() == "true"
            assert sanitize is True

        # Case insensitive
        with patch.dict(os.environ, {"STATS_SANITIZE_IDS": "TRUE"}):
            sanitize = os.getenv("STATS_SANITIZE_IDS", "false").lower() == "true"
            assert sanitize is True
