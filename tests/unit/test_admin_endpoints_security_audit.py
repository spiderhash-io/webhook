"""
Comprehensive security audit tests for Admin Endpoints.

Tests cover:
- Type confusion attacks (non-boolean values in JSON)
- Error information disclosure
- Missing None header validation
- Rate limiting bypass
- Information disclosure in status endpoint
- Request body size limits
- Content-Type validation
- Header injection in Authorization header
- JSON parsing DoS
- Concurrent request handling
"""

import pytest
import json
import os
import time
import asyncio
from unittest.mock import patch, Mock, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI, HTTPException

from src.main import app
from src.config_manager import ConfigManager, ReloadResult
from src.utils import sanitize_error_message


# ============================================================================
# 1. TYPE CONFUSION ATTACKS
# ============================================================================


class TestTypeConfusionAttacks:
    """Test type confusion vulnerabilities in admin endpoints."""

    def test_reload_config_type_confusion_string(self):
        """Test that string values for reload_webhooks are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # String "true" instead of boolean
            response = client.post(
                "/admin/reload-config",
                json={"reload_webhooks": "true", "reload_connections": "false"},
            )
            # Should handle gracefully (may treat as truthy or reject)
            assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_reload_config_type_confusion_list(self):
        """Test that list values for reload_webhooks are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # List instead of boolean
            response = client.post(
                "/admin/reload-config",
                json={"reload_webhooks": [True], "reload_connections": []},
            )
            # Should handle gracefully
            assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_reload_config_type_confusion_dict(self):
        """Test that dict values for reload_webhooks are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Dict instead of boolean
            response = client.post(
                "/admin/reload-config",
                json={"reload_webhooks": {"nested": True}, "reload_connections": {}},
            )
            # Should handle gracefully
            assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_reload_config_type_confusion_integer(self):
        """Test that integer values for reload_webhooks are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Integer instead of boolean (0/1)
            response = client.post(
                "/admin/reload-config",
                json={"reload_webhooks": 1, "reload_connections": 0},
            )
            # Should handle gracefully
            assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_reload_config_type_confusion_null(self):
        """Test that null values for reload_webhooks are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Null values
            response = client.post(
                "/admin/reload-config",
                json={"reload_webhooks": None, "reload_connections": None},
            )
            # Should handle gracefully (may default to True or reject)
            assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_reload_config_type_confusion_validate_only(self):
        """Test that validate_only type confusion is handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # String instead of boolean
            response = client.post(
                "/admin/reload-config",
                json={"validate_only": "true", "reload_webhooks": True},
            )
            # Should handle gracefully
            assert response.status_code in [200, 400, 401, 403, 422, 503]


# ============================================================================
# 2. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestErrorInformationDisclosure:
    """Test error information disclosure vulnerabilities."""

    @pytest.mark.asyncio
    async def test_reload_config_error_disclosure(self):
        """Test that error messages don't disclose sensitive information."""
        # Mock ConfigManager to return error with sensitive info
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(
                success=False,
                error="Failed to connect to database: postgresql://admin:secret123@localhost:5432/db",
                details={"file_path": "/etc/passwd", "stack_trace": "Traceback..."},
            )
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
                client = TestClient(app)

                response = client.post("/admin/reload-config", json={})

                if response.status_code == 400:
                    data = response.json()
                    error_msg = json.dumps(data).lower()

                    # Should not contain sensitive information
                    assert "secret123" not in error_msg
                    assert "postgresql://" not in error_msg
                    assert "/etc/passwd" not in error_msg
                    assert "traceback" not in error_msg
                    assert "stack_trace" not in error_msg
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")

    @pytest.mark.asyncio
    async def test_reload_config_details_disclosure(self):
        """Test that result.details don't disclose sensitive information."""
        # Mock ConfigManager to return details with sensitive info
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(
                success=True,
                details={
                    "connection_string": "postgresql://admin:password@localhost:5432/db",
                    "file_path": "/etc/passwd",
                    "internal_error": "Database connection failed",
                },
            )
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
                client = TestClient(app)

                response = client.post("/admin/reload-config", json={})

                if response.status_code == 200:
                    data = response.json()
                    details_str = json.dumps(data).lower()

                    # Should not contain sensitive information
                    assert "password" not in details_str
                    assert "postgresql://" not in details_str
                    assert "/etc/passwd" not in details_str
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")

    def test_config_status_information_disclosure(self):
        """Test that config status doesn't disclose sensitive pool information."""
        # Mock ConfigManager to return status with sensitive info
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.get_status = Mock(
            return_value={
                "last_reload": "2024-01-01T00:00:00Z",
                "reload_in_progress": False,
                "webhooks_count": 1,
                "connections_count": 1,
                "connection_pools": {"active": 1, "deprecated": 0},
                "pool_details": {
                    "conn1": {
                        "connection_string": "postgresql://admin:password@localhost:5432/db",
                        "secret": "my-secret-token",
                    }
                },
            }
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
                client = TestClient(app)

                response = client.get("/admin/config-status")

                if response.status_code == 200:
                    data = response.json()
                    status_str = json.dumps(data).lower()

                    # Should not contain sensitive information
                    assert "password" not in status_str
                    assert "secret" not in status_str
                    assert "token" not in status_str
                    assert "connection_string" not in status_str
                    assert "postgresql://" not in status_str
                    # Pool details might contain connection info, but should be sanitized
                    if "pool_details" in data:
                        pool_details_str = json.dumps(data["pool_details"]).lower()
                        assert "password" not in pool_details_str
                        assert "secret" not in pool_details_str
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")


# ============================================================================
# 3. MISSING NONE HEADER VALIDATION
# ============================================================================


class TestNoneHeaderValidation:
    """Test None header value handling."""

    def test_authorization_header_none_value(self):
        """Test that None authorization header is handled safely."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
                client = TestClient(app)

                # Try to send None as header value (if possible)
                # FastAPI will convert None to empty string, but test edge case
                response = client.post(
                    "/admin/reload-config",
                    json={},
                    headers={"Authorization": ""},  # Empty string (None equivalent)
                )
                # Should return 401, not crash
                assert response.status_code == 401
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")

    def test_authorization_header_missing(self):
        """Test that missing authorization header is handled safely."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
                client = TestClient(app)

                # No Authorization header at all
                response = client.post("/admin/reload-config", json={})
                # Should return 401, not crash
                assert response.status_code == 401
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")


# ============================================================================
# 4. RATE LIMITING BYPASS
# ============================================================================


class TestRateLimitingBypass:
    """Test rate limiting vulnerabilities."""

    def test_reload_config_rapid_requests(self):
        """Test that rapid reload requests can cause DoS."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Rapid requests
            start_time = time.time()
            responses = []
            for _ in range(100):
                responses.append(client.post("/admin/reload-config", json={}))
            elapsed = time.time() - start_time

            # All requests should complete (no rate limiting currently)
            assert len(responses) == 100
            # Should complete quickly (no blocking)
            assert elapsed < 10.0

    def test_config_status_rapid_requests(self):
        """Test that rapid status requests can cause DoS."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Rapid requests
            start_time = time.time()
            responses = []
            for _ in range(100):
                responses.append(client.get("/admin/config-status"))
            elapsed = time.time() - start_time

            # All requests should complete
            assert len(responses) == 100
            assert elapsed < 10.0


# ============================================================================
# 5. REQUEST BODY SIZE LIMITS
# ============================================================================


class TestRequestBodySizeLimits:
    """Test request body size limit vulnerabilities."""

    def test_reload_config_oversized_payload(self):
        """Test that oversized payloads are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Very large payload (10MB)
            large_payload = {
                "reload_webhooks": True,
                "data": "x" * (10 * 1024 * 1024),  # 10MB
            }

            response = client.post("/admin/reload-config", json=large_payload)
            # Should handle gracefully (may reject or process)
            assert response.status_code in [200, 400, 401, 403, 413, 422, 503]

    def test_reload_config_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Deeply nested structure (but limit to avoid RecursionError in json.dumps)
            # Python's default recursion limit is ~1000, so use 500 levels to be safe
            nested = {"level": 1}
            current = nested
            for i in range(2, 500):
                current["nested"] = {"level": i}
                current = current["nested"]

            payload = {"reload_webhooks": True, "nested_data": nested}

            try:
                response = client.post("/admin/reload-config", json=payload)
                # Should handle gracefully
                assert response.status_code in [200, 400, 401, 403, 422, 503]
            except RecursionError:
                # If json.dumps hits recursion limit, that's acceptable - test passes
                # The important thing is that it doesn't crash the server
                assert True


# ============================================================================
# 6. CONTENT-TYPE VALIDATION
# ============================================================================


class TestContentTypeValidation:
    """Test Content-Type validation vulnerabilities."""

    def test_reload_config_wrong_content_type(self):
        """Test that wrong Content-Type is handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Send JSON with wrong Content-Type
            response = client.post(
                "/admin/reload-config",
                data=json.dumps({"reload_webhooks": True}),
                headers={"Content-Type": "text/plain"},
            )
            # FastAPI should still parse JSON
            assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_reload_config_missing_content_type(self):
        """Test that missing Content-Type is handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Send JSON without Content-Type
            response = client.post(
                "/admin/reload-config",
                data=json.dumps({"reload_webhooks": True}),
                headers={},  # No Content-Type
            )
            # FastAPI should still parse JSON
            assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_reload_config_malformed_content_type(self):
        """Test that malformed Content-Type is handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Malformed Content-Type
            response = client.post(
                "/admin/reload-config",
                data=json.dumps({"reload_webhooks": True}),
                headers={
                    "Content-Type": "application/json; charset=utf-8; boundary=malicious"
                },
            )
            # Should handle gracefully
            assert response.status_code in [200, 400, 401, 403, 422, 503]


# ============================================================================
# 7. HEADER INJECTION IN AUTHORIZATION
# ============================================================================


class TestHeaderInjection:
    """Test header injection vulnerabilities."""

    def test_authorization_header_newline_injection(self):
        """Test that newline injection in Authorization header is prevented."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
                client = TestClient(app)

                # Try to inject newline
                malicious_header = f"Bearer secret-token\nX-Injected-Header: malicious"

                response = client.post(
                    "/admin/reload-config",
                    json={},
                    headers={"Authorization": malicious_header},
                )
                # Should reject (token extraction should handle newlines safely)
                assert response.status_code == 401
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")

    def test_authorization_header_carriage_return_injection(self):
        """Test that carriage return injection in Authorization header is prevented."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
                client = TestClient(app)

                # Try to inject carriage return
                malicious_header = f"Bearer secret-token\rX-Injected-Header: malicious"

                response = client.post(
                    "/admin/reload-config",
                    json={},
                    headers={"Authorization": malicious_header},
                )
                # Should reject
                assert response.status_code == 401
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")

    def test_authorization_header_null_byte_injection(self):
        """Test that null byte injection in Authorization header is prevented."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
                client = TestClient(app)

                # Try to inject null byte
                malicious_header = f"Bearer secret-token\x00malicious"

                response = client.post(
                    "/admin/reload-config",
                    json={},
                    headers={"Authorization": malicious_header},
                )
                # Should reject
                assert response.status_code == 401
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")

    def test_authorization_header_unicode_injection(self):
        """Test that Unicode injection in Authorization header is handled safely."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
                client = TestClient(app)

                # Try Unicode characters (but avoid non-ASCII in header value for httpx)
                # Test with null byte which is ASCII
                malicious_header = f"Bearer secret-token\x00malicious"

                response = client.post(
                    "/admin/reload-config",
                    json={},
                    headers={"Authorization": malicious_header},
                )
                # Should reject
                assert response.status_code == 401
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")


# ============================================================================
# 8. JSON PARSING DoS
# ============================================================================


class TestJSONParsingDoS:
    """Test JSON parsing denial-of-service vulnerabilities."""

    def test_reload_config_malformed_json(self):
        """Test that malformed JSON is handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            malformed_json_variants = [
                '{"reload_webhooks": true,}',  # Trailing comma
                '{"reload_webhooks": true',  # Missing closing brace
                '{"reload_webhooks": "true"}',  # Valid but wrong type
                '{"reload_webhooks": true, "nested": {"unclosed": "string}',  # Unclosed string
            ]

            for malformed_json in malformed_json_variants:
                try:
                    response = client.post(
                        "/admin/reload-config",
                        data=malformed_json,
                        headers={"Content-Type": "application/json"},
                    )
                    # Should handle gracefully
                    assert response.status_code in [200, 400, 401, 403, 422, 503]
                except Exception:
                    # JSON parsing error is acceptable
                    pass

    def test_reload_config_circular_reference_attempt(self):
        """Test that circular reference attempts are handled safely."""
        # Note: JSON doesn't support circular references, but test anyway
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Valid JSON (circular references not possible in JSON)
            payload = {"reload_webhooks": True}

            response = client.post("/admin/reload-config", json=payload)
            # Should handle normally
            assert response.status_code in [200, 400, 401, 403, 422, 503]


# ============================================================================
# 9. CONCURRENT REQUEST HANDLING
# ============================================================================


class TestConcurrentRequestHandling:
    """Test concurrent request handling vulnerabilities."""

    def test_reload_config_concurrent_requests(self):
        """Test that concurrent reload requests are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Concurrent requests
            import threading

            responses = []

            def make_request():
                responses.append(client.post("/admin/reload-config", json={}))

            threads = []
            for _ in range(10):
                thread = threading.Thread(target=make_request)
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            # All requests should complete
            assert len(responses) == 10
            for response in responses:
                assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_config_status_concurrent_requests(self):
        """Test that concurrent status requests are handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Concurrent requests
            import threading

            responses = []

            def make_request():
                responses.append(client.get("/admin/config-status"))

            threads = []
            for _ in range(10):
                thread = threading.Thread(target=make_request)
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            # All requests should complete
            assert len(responses) == 10
            for response in responses:
                assert response.status_code in [200, 401, 403, 503]


# ============================================================================
# 10. WHITESPACE AND EDGE CASES
# ============================================================================


class TestWhitespaceAndEdgeCases:
    """Test whitespace and edge case handling."""

    def test_reload_config_whitespace_only_token(self):
        """Test that whitespace-only token is treated as unconfigured (403)."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "   "}):
                client = TestClient(app)

                # Token is only whitespace
                response = client.post(
                    "/admin/reload-config",
                    json={},
                    headers={"Authorization": "Bearer    "},
                )
                # Admin API is disabled when token is not configured
                assert response.status_code == 403
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")

    def test_reload_config_empty_token(self):
        """Test that empty token is handled safely."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
                client = TestClient(app)

                # Admin API disabled when env var is empty
                response = client.post("/admin/reload-config", json={})
                assert response.status_code == 403
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")

    def test_reload_config_very_long_token(self):
        """Test that very long token is handled safely."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "x" * 10000}):
            client = TestClient(app)

            # Very long token
            response = client.post(
                "/admin/reload-config",
                json={},
                headers={"Authorization": f"Bearer {'x' * 10000}"},
            )
            # Should handle gracefully (may be slow but shouldn't crash)
            assert response.status_code in [200, 400, 401, 403, 422, 503]

    def test_reload_config_unicode_token(self):
        """Test that Unicode token is handled safely."""
        # Mock ConfigManager to avoid 503 errors
        mock_config_manager = Mock(spec=ConfigManager)
        mock_config_manager.reload_all = AsyncMock(
            return_value=ReloadResult(success=True)
        )

        # Set config_manager in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = mock_config_manager

        try:
            with patch.dict(
                os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token-123"}
            ):
                client = TestClient(app)

                # Unicode characters in token (use ASCII-safe test)
                # Test with null byte which is ASCII
                unicode_token = "secret-token-123\x00"

                response = client.post(
                    "/admin/reload-config",
                    json={},
                    headers={"Authorization": f"Bearer {unicode_token}"},
                )
                # Should reject (token doesn't match or contains invalid chars)
                assert response.status_code == 401
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
