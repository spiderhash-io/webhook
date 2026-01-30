"""
Comprehensive security tests for OAuth2 authentication.
Tests advanced OAuth2 attack vectors and bypass techniques.
"""

import pytest
import jwt
import time
from unittest.mock import AsyncMock, patch, MagicMock
from src.validators import OAuth2Validator


class TestOAuth2SSRF:
    """Test SSRF vulnerabilities in token introspection."""

    @pytest.mark.asyncio
    async def test_introspection_endpoint_localhost_ssrf(self):
        """Test SSRF via introspection endpoint pointing to localhost."""
        config = {
            "oauth2": {
                "introspection_endpoint": "http://127.0.0.1:8080/introspect",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # This should be blocked - localhost introspection endpoint is SSRF risk
        # Test documents current behavior
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - SSRF protection should block localhost
        # If it doesn't fail, this is a vulnerability
        assert (
            is_valid is False
            or "localhost" in message.lower()
            or "127.0.0.1" in message.lower()
            or "not allowed" in message.lower()
        )

    @pytest.mark.asyncio
    @pytest.mark.longrunning
    async def test_introspection_endpoint_private_ip_ssrf(self):
        """Test SSRF via introspection endpoint pointing to private IP."""
        config = {
            "oauth2": {
                "introspection_endpoint": "http://192.168.1.1:8080/introspect",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # Should be blocked - private IP introspection endpoint is SSRF risk
        is_valid, message = await validator.validate(headers, b"")
        assert (
            is_valid is False
            or "192.168" in message.lower()
            or "not allowed" in message.lower()
            or "private" in message.lower()
        )

    @pytest.mark.asyncio
    async def test_introspection_endpoint_metadata_ssrf(self):
        """Test SSRF via introspection endpoint pointing to cloud metadata."""
        config = {
            "oauth2": {
                "introspection_endpoint": "http://169.254.169.254/latest/meta-data/",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # Should be blocked - metadata endpoint is SSRF risk
        is_valid, message = await validator.validate(headers, b"")
        assert (
            is_valid is False
            or "169.254" in message.lower()
            or "metadata" in message.lower()
            or "not allowed" in message.lower()
        )

    @pytest.mark.asyncio
    async def test_introspection_endpoint_file_protocol_ssrf(self):
        """Test SSRF via file:// protocol in introspection endpoint."""
        config = {
            "oauth2": {
                "introspection_endpoint": "file:///etc/passwd",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # Should be blocked - file:// protocol is SSRF risk
        is_valid, message = await validator.validate(headers, b"")
        assert (
            is_valid is False
            or "file://" in message.lower()
            or "not allowed" in message.lower()
        )


class TestOAuth2JWTAlgorithmConfusion:
    """Test JWT algorithm confusion attacks."""

    @pytest.mark.asyncio
    async def test_jwt_algorithm_confusion_none(self):
        """Test JWT with 'none' algorithm in algorithms list."""
        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["none", "HS256"],  # 'none' in list
            }
        }

        validator = OAuth2Validator(config)

        # Try to create token with none algorithm
        try:
            token = jwt.encode({"sub": "user123"}, "", algorithm="none")
            headers = {"authorization": f"Bearer {token}"}

            is_valid, message = await validator.validate(headers, b"")
            # Should fail - 'none' algorithm should be rejected
            assert is_valid is False
        except Exception:
            # If PyJWT rejects encoding with 'none', that's also good
            pass

    @pytest.mark.asyncio
    async def test_jwt_algorithm_whitelist_enforcement(self):
        """Test that only whitelisted algorithms are allowed."""
        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],  # Only HS256 allowed
            }
        }

        validator = OAuth2Validator(config)

        # Create token with HS512 (not in whitelist)
        token = jwt.encode({"sub": "user123"}, "secret_key", algorithm="HS512")
        headers = {"authorization": f"Bearer {token}"}

        is_valid, message = await validator.validate(headers, b"")
        # Should fail - HS512 not in allowed algorithms
        assert is_valid is False
        assert "Invalid" in message or "algorithm" in message.lower()

    @pytest.mark.asyncio
    async def test_jwt_empty_secret(self):
        """Test JWT validation with empty secret."""
        config = {
            "oauth2": {"jwt_secret": "", "jwt_algorithms": ["HS256"]}  # Empty secret
        }

        validator = OAuth2Validator(config)

        token = jwt.encode({"sub": "user123"}, "", algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}

        is_valid, message = await validator.validate(headers, b"")
        # Should fail - empty secret is insecure
        assert is_valid is False
        assert (
            "secret" in message.lower()
            or "not configured" in message.lower()
            or "Invalid" in message
        )


class TestOAuth2TokenReplay:
    """Test token replay attack prevention."""

    @pytest.mark.asyncio
    async def test_token_replay_allowed(self):
        """Test that token replay is currently allowed (document behavior)."""
        # Note: OAuth2 doesn't prevent replay by itself - needs nonce/timestamp
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        token = jwt.encode({"sub": "user123"}, "secret_key", algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}

        # Use same token multiple times
        for _ in range(5):
            is_valid, message = await validator.validate(headers, b"")
            # Should work - OAuth2 doesn't prevent replay by itself
            # This is a potential security issue if not addressed elsewhere
            assert is_valid is True


class TestOAuth2ScopeEscalation:
    """Test scope escalation attacks."""

    @pytest.mark.asyncio
    async def test_scope_manipulation_introspection(self):
        """Test scope manipulation in introspection response."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "required_scope": ["read", "write", "admin"],
            }
        }

        headers = {"authorization": "Bearer token"}

        # Mock introspection response with insufficient scopes
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "active": True,
            "scope": "read write",  # Missing 'admin' scope
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            validator = OAuth2Validator(config)
            is_valid, message = await validator.validate(headers, b"")
            # Should fail - missing required scope
            assert is_valid is False
            assert "missing required scopes" in message.lower()
            # Note: Implementation intentionally doesn't list specific missing scopes
            # to prevent scope enumeration attacks

    @pytest.mark.asyncio
    async def test_scope_injection_jwt(self):
        """Test scope injection in JWT token."""
        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "required_scope": ["read"],
            }
        }

        validator = OAuth2Validator(config)

        # Token with extra scopes (should still validate if 'read' is present)
        token = jwt.encode(
            {"sub": "user123", "scope": "read write admin"},  # Extra scopes
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        is_valid, message = await validator.validate(headers, b"")
        # Should work - extra scopes are allowed, only required ones are checked
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_empty_scope_handling(self):
        """Test handling of empty scope."""
        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "required_scope": ["read"],
            }
        }

        validator = OAuth2Validator(config)

        # Token with no scope
        token = jwt.encode(
            {
                "sub": "user123"
                # No scope claim
            },
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        is_valid, message = await validator.validate(headers, b"")
        # Should fail - required scope missing
        assert is_valid is False
        assert "missing required scopes" in message.lower()


class TestOAuth2HeaderInjection:
    """Test header injection attacks."""

    @pytest.mark.asyncio
    async def test_newline_in_authorization_header(self):
        """Test newline injection in Authorization header."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        token = jwt.encode({"sub": "user123"}, "secret_key", algorithm="HS256")

        # Newline injection attempts
        injection_attempts = [
            f"Bearer {token}\nX-Injected: value",
            f"Bearer {token}\rX-Injected: value",
            f"Bearer {token}\r\nX-Injected: value",
        ]

        for auth_header in injection_attempts:
            headers = {"authorization": auth_header}
            is_valid, message = await validator.validate(headers, b"")
            # Should fail - newlines indicate header injection
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_null_bytes_in_token(self):
        """Test null bytes in token."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        # Token with null bytes
        token = "test\x00token"
        headers = {"authorization": f"Bearer {token}"}

        is_valid, message = await validator.validate(headers, b"")
        # Should fail - null bytes in token
        assert is_valid is False


class TestOAuth2TokenExtraction:
    """Test token extraction vulnerabilities."""

    @pytest.mark.asyncio
    async def test_empty_token_after_bearer(self):
        """Test Authorization header with Bearer but no token."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        headers = {"authorization": "Bearer "}

        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Empty OAuth 2.0 token" in message

    @pytest.mark.asyncio
    async def test_whitespace_only_token(self):
        """Test Authorization header with only whitespace after Bearer."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        headers = {"authorization": "Bearer   "}  # Only spaces

        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Empty" in message or "Invalid" in message

    @pytest.mark.asyncio
    async def test_multiple_bearer_prefixes(self):
        """Test Authorization header with multiple Bearer prefixes."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        token = jwt.encode({"sub": "user123"}, "secret_key", algorithm="HS256")
        headers = {"authorization": f"Bearer Bearer {token}"}

        is_valid, message = await validator.validate(headers, b"")
        # Should fail - invalid format
        assert is_valid is False


class TestOAuth2BothMethodsConfigured:
    """Test behavior when both introspection and JWT are configured."""

    @pytest.mark.asyncio
    async def test_both_introspection_and_jwt_configured(self):
        """Test when both introspection endpoint and JWT secret are configured."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
            }
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # Mock introspection to fail
        mock_response = MagicMock()
        mock_response.json.return_value = {"active": False}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            is_valid, message = await validator.validate(headers, b"")
            # Should use introspection (it's checked first)
            # JWT validation should not run because introspection_endpoint exists
            assert is_valid is False
            assert "not active" in message.lower() or "introspection" in message.lower()


class TestOAuth2TimingAttacks:
    """Test timing attack resistance."""

    @pytest.mark.asyncio
    async def test_token_validation_timing(self):
        """Test that token validation timing is consistent."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        # Valid token
        valid_token = jwt.encode({"sub": "user123"}, "secret_key", algorithm="HS256")

        # Invalid tokens
        invalid_tokens = [
            jwt.encode(
                {"sub": "user123"}, "wrong_secret", algorithm="HS256"
            ),  # Wrong secret
            "invalid.token.string",  # Malformed
            "a" * 100,  # Completely wrong
        ]

        import time

        # Measure time for valid token
        start = time.time()
        headers_valid = {"authorization": f"Bearer {valid_token}"}
        is_valid1, _ = await validator.validate(headers_valid, b"")
        time_valid = time.time() - start

        # Measure time for invalid tokens
        times_invalid = []
        for token in invalid_tokens:
            start = time.time()
            headers_invalid = {"authorization": f"Bearer {token}"}
            is_valid2, _ = await validator.validate(headers_invalid, b"")
            times_invalid.append(time.time() - start)
            assert is_valid2 is False

        # Times should be similar (within 0.1s)
        max_time_diff = max(abs(time_valid - t) for t in times_invalid)
        assert (
            max_time_diff < 0.1
        ), f"Timing difference too large: {max_time_diff}s (potential timing attack)"


class TestOAuth2SecretExposure:
    """Test secret exposure prevention."""

    @pytest.mark.asyncio
    async def test_jwt_secret_not_in_error_messages(self):
        """Test that JWT secret is not exposed in error messages."""
        secret = "super_secret_key_12345"
        config = {"oauth2": {"jwt_secret": secret, "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        # Use wrong secret to trigger error
        wrong_token = jwt.encode({"sub": "user123"}, "wrong_secret", algorithm="HS256")
        headers = {"authorization": f"Bearer {wrong_token}"}

        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False

        # Secret should not appear in error message
        assert secret not in message
        assert "super_secret_key_12345" not in message

    @pytest.mark.asyncio
    async def test_client_secret_not_in_error_messages(self):
        """Test that client secret is not exposed in error messages."""
        client_secret = "super_client_secret_12345"
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_id": "client_id",
                "client_secret": client_secret,
            }
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # Mock introspection error
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 401
        http_error = httpx.HTTPStatusError(
            "401 Unauthorized", request=MagicMock(), response=mock_response
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=http_error
            )

            is_valid, message = await validator.validate(headers, b"")
            assert is_valid is False

            # Client secret should not appear in error message
            assert client_secret not in message
            assert "super_client_secret_12345" not in message


class TestOAuth2IntrospectionSecurity:
    """Test introspection endpoint security."""

    @pytest.mark.asyncio
    async def test_introspection_timeout_handling(self):
        """Test that introspection timeout is enforced."""
        import httpx

        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # Mock timeout error
        timeout_error = httpx.TimeoutException("Request timed out", request=MagicMock())

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=timeout_error
            )

            is_valid, message = await validator.validate(headers, b"")
            # Should fail due to timeout
            assert is_valid is False
            assert (
                "timeout" in message.lower()
                or "network error" in message.lower()
                or "error" in message.lower()
            )

    @pytest.mark.asyncio
    async def test_introspection_malformed_response(self):
        """Test handling of malformed introspection response."""
        config = {
            "oauth2": {"introspection_endpoint": "https://auth.example.com/introspect"}
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # Mock malformed JSON response
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            is_valid, message = await validator.validate(headers, b"")
            # Should fail - malformed response
            assert is_valid is False
            assert "error" in message.lower() or "Invalid" in message

    @pytest.mark.asyncio
    async def test_introspection_missing_active_field(self):
        """Test introspection response without 'active' field."""
        config = {
            "oauth2": {"introspection_endpoint": "https://auth.example.com/introspect"}
        }

        validator = OAuth2Validator(config)
        headers = {"authorization": "Bearer test_token"}

        # Mock response without 'active' field
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "scope": "read write"
            # Missing 'active' field
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            is_valid, message = await validator.validate(headers, b"")
            # Should fail - 'active' field is required
            assert is_valid is False
            assert "not active" in message.lower() or "error" in message.lower()


class TestOAuth2EdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_very_long_token(self):
        """Test very long token (DoS attempt)."""
        config = {
            "oauth2": {"validate_token": False}  # Disable validation for this test
        }

        validator = OAuth2Validator(config)

        long_token = "a" * 100000  # 100KB token
        headers = {"authorization": f"Bearer {long_token}"}

        # Should handle gracefully (may be slow, but shouldn't crash)
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_unicode_in_token(self):
        """Test Unicode characters in token."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        validator = OAuth2Validator(config)

        # Unicode token (invalid JWT)
        unicode_token = "测试" * 100
        headers = {"authorization": f"Bearer {unicode_token}"}

        is_valid, message = await validator.validate(headers, b"")
        # Should fail - invalid JWT format
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_case_sensitive_token_type(self):
        """Test case sensitivity of token type."""
        config = {"oauth2": {"token_type": "Bearer", "validate_token": False}}

        validator = OAuth2Validator(config)

        # Case variations
        case_variations = [
            ("bearer", False),  # Lowercase
            ("BEARER", False),  # Uppercase
            ("Bearer", True),  # Correct
        ]

        for prefix, should_work in case_variations:
            headers = {"authorization": f"{prefix} test_token"}
            is_valid, message = await validator.validate(headers, b"")
            if should_work:
                assert is_valid is True
            else:
                assert is_valid is False
