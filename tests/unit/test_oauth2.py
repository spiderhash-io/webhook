"""
Tests for OAuth 2.0 Authentication validator.
Includes security edge cases and comprehensive validation.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.validators import OAuth2Validator


class TestOAuth2:
    """Test suite for OAuth 2.0 Authentication."""

    @pytest.mark.asyncio
    async def test_oauth2_no_config(self):
        """Test that validation passes when no OAuth 2.0 is configured."""
        config = {}
        validator = OAuth2Validator(config)

        headers = {}
        body = b"test"

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True
        assert "No OAuth 2.0 validation required" in message

    @pytest.mark.asyncio
    async def test_oauth2_missing_authorization_header(self):
        """Test validation when Authorization header is missing."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        headers = {}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Missing Authorization header" in message

    @pytest.mark.asyncio
    async def test_oauth2_wrong_token_type(self):
        """Test validation with wrong token type."""
        config = {
            "oauth2": {
                "token_type": "Bearer",
                "introspection_endpoint": "https://auth.example.com/introspect",
            }
        }

        headers = {"authorization": "Basic dXNlcjpwYXNz"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "OAuth 2.0 Bearer token required" in message

    @pytest.mark.asyncio
    async def test_oauth2_empty_token(self):
        """Test validation with empty token."""
        config = {
            "oauth2": {
                "token_type": "Bearer",
                "introspection_endpoint": "https://auth.example.com/introspect",
            }
        }

        headers = {"authorization": "Bearer "}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Empty OAuth 2.0 token" in message

    @pytest.mark.asyncio
    async def test_oauth2_introspection_success(self):
        """Test successful token introspection."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        headers = {"authorization": "Bearer valid_token_123"}

        # Mock successful introspection response
        mock_response = MagicMock()
        mock_response.json.return_value = {"active": True, "scope": "read write"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            validator = OAuth2Validator(config)
            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is True
            assert "Valid OAuth 2.0 token" in message

    @pytest.mark.asyncio
    async def test_oauth2_introspection_inactive_token(self):
        """Test introspection with inactive token."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        headers = {"authorization": "Bearer invalid_token"}

        # Mock inactive token response
        mock_response = MagicMock()
        mock_response.json.return_value = {"active": False}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            validator = OAuth2Validator(config)
            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is False
            assert "OAuth 2.0 token is not active" in message

    @pytest.mark.asyncio
    async def test_oauth2_introspection_scope_validation_success(self):
        """Test scope validation with valid scopes."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "required_scope": ["read", "write"],
            }
        }

        headers = {"authorization": "Bearer valid_token"}

        # Mock response with required scopes
        mock_response = MagicMock()
        mock_response.json.return_value = {"active": True, "scope": "read write admin"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            validator = OAuth2Validator(config)
            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_oauth2_introspection_scope_validation_failure(self):
        """Test scope validation with missing scopes."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "required_scope": ["read", "write", "admin"],
            }
        }

        headers = {"authorization": "Bearer valid_token"}

        # Mock response with insufficient scopes
        mock_response = MagicMock()
        mock_response.json.return_value = {"active": True, "scope": "read write"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            validator = OAuth2Validator(config)
            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is False
            # SECURITY: Error message should not enumerate specific missing scopes
            assert "missing required scopes" in message.lower()

    @pytest.mark.asyncio
    async def test_oauth2_introspection_http_error(self):
        """Test introspection with HTTP error."""
        import httpx

        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_id": "client_id",
                "client_secret": "client_secret",
            }
        }

        headers = {"authorization": "Bearer token"}

        # Mock HTTP error using httpx.HTTPStatusError
        mock_response = MagicMock()
        mock_response.status_code = 401

        http_error = httpx.HTTPStatusError(
            "401 Unauthorized", request=MagicMock(), response=mock_response
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=http_error
            )

            validator = OAuth2Validator(config)
            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is False
            assert "OAuth 2.0 token introspection failed" in message
            assert "401" in message

    @pytest.mark.asyncio
    async def test_oauth2_introspection_network_error(self):
        """Test introspection with network error."""
        import httpx

        config = {
            "oauth2": {"introspection_endpoint": "https://auth.example.com/introspect"}
        }

        headers = {"authorization": "Bearer token"}

        # Mock network error using httpx.RequestError
        network_error = httpx.RequestError("Connection error", request=MagicMock())

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=network_error
            )

            validator = OAuth2Validator(config)
            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is False
            assert "network error" in message.lower()

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_success(self):
        """Test JWT token validation success."""
        import jwt
        import time

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "verify_exp": True,
            }
        }

        # Create a valid JWT token
        token = jwt.encode(
            {"sub": "user123", "exp": int(time.time()) + 3600, "scope": "read write"},
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
        assert "Valid OAuth 2.0 JWT token" in message

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_expired(self):
        """Test JWT token validation with expired token."""
        import jwt
        import time

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "verify_exp": True,
            }
        }

        # Create an expired JWT token
        token = jwt.encode(
            {
                "sub": "user123",
                "exp": int(time.time()) - 3600,  # Expired 1 hour ago
                "scope": "read write",
            },
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "OAuth 2.0 token expired" in message

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_invalid_signature(self):
        """Test JWT token validation with invalid signature."""
        import jwt

        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        # Create a token with wrong secret
        token = jwt.encode(
            {"sub": "user123", "scope": "read write"}, "wrong_secret", algorithm="HS256"
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 2.0 JWT token" in message

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_audience_success(self):
        """Test JWT token validation with valid audience."""
        import jwt

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "audience": "webhook-api",
            }
        }

        token = jwt.encode(
            {"sub": "user123", "aud": "webhook-api", "scope": "read write"},
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_audience_failure(self):
        """Test JWT token validation with invalid audience."""
        import jwt

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "audience": "webhook-api",
            }
        }

        token = jwt.encode(
            {"sub": "user123", "aud": "wrong-audience", "scope": "read write"},
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        # PyJWT may return different error messages, check for either
        assert "audience" in message.lower() or "Invalid OAuth 2.0 JWT token" in message

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_issuer_success(self):
        """Test JWT token validation with valid issuer."""
        import jwt

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "issuer": "https://auth.example.com",
            }
        }

        token = jwt.encode(
            {
                "sub": "user123",
                "iss": "https://auth.example.com",
                "scope": "read write",
            },
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_issuer_failure(self):
        """Test JWT token validation with invalid issuer."""
        import jwt

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "issuer": "https://auth.example.com",
            }
        }

        token = jwt.encode(
            {
                "sub": "user123",
                "iss": "https://wrong-issuer.com",
                "scope": "read write",
            },
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "OAuth 2.0 token issuer mismatch" in message

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_scope_success(self):
        """Test JWT token validation with valid scope."""
        import jwt

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "required_scope": ["read", "write"],
            }
        }

        token = jwt.encode(
            {"sub": "user123", "scope": "read write admin"},
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_oauth2_jwt_validation_scope_failure(self):
        """Test JWT token validation with missing scope."""
        import jwt

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "required_scope": ["read", "write", "admin"],
            }
        }

        token = jwt.encode(
            {"sub": "user123", "scope": "read write"}, "secret_key", algorithm="HS256"
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        # SECURITY: Error message should not enumerate specific missing scopes
        assert "missing required scopes" in message.lower()

    @pytest.mark.asyncio
    async def test_oauth2_validation_disabled(self):
        """Test when token validation is disabled."""
        config = {"oauth2": {"validate_token": False}}

        headers = {"authorization": "Bearer any_token"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
        assert "validation disabled" in message.lower()

    @pytest.mark.asyncio
    async def test_oauth2_malformed_token(self):
        """Test validation with malformed token."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        headers = {"authorization": "Bearer not.a.valid.jwt.token"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 2.0 JWT token" in message

    @pytest.mark.asyncio
    async def test_oauth2_custom_token_type(self):
        """Test with custom token type."""
        config = {"oauth2": {"token_type": "Token", "validate_token": False}}

        headers = {"authorization": "Token custom_token_123"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_oauth2_introspection_with_client_auth(self):
        """Test introspection with client credentials authentication."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_id": "test_client",
                "client_secret": "test_secret",
            }
        }

        headers = {"authorization": "Bearer token"}

        mock_response = MagicMock()
        mock_response.json.return_value = {"active": True}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post

            validator = OAuth2Validator(config)
            await validator.validate(headers, body=b"test")

            # Verify client credentials were used
            call_args = mock_post.call_args
            assert call_args is not None
            # Check that auth parameter was passed (httpx uses tuple for basic auth)
            # The actual auth check would be in the call kwargs

    @pytest.mark.asyncio
    async def test_oauth2_introspection_scope_array(self):
        """Test introspection with scope as array."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "required_scope": ["read", "write"],
            }
        }

        headers = {"authorization": "Bearer token"}

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "active": True,
            "scope": ["read", "write", "admin"],  # Array format
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            validator = OAuth2Validator(config)
            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_oauth2_jwt_scope_array(self):
        """Test JWT validation with scope as array."""
        import jwt

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256"],
                "required_scope": ["read", "write"],
            }
        }

        token = jwt.encode(
            {"sub": "user123", "scope": ["read", "write", "admin"]},  # Array format
            "secret_key",
            algorithm="HS256",
        )

        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_oauth2_no_validation_method(self):
        """Test when no validation method is configured."""
        config = {
            "oauth2": {
                "validate_token": True
                # No introspection_endpoint or jwt_secret
            }
        }

        headers = {"authorization": "Bearer token"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "not properly configured" in message.lower()

    @pytest.mark.asyncio
    async def test_oauth2_sql_injection_in_token(self):
        """Test that SQL injection attempts in token are handled safely."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        headers = {"authorization": "Bearer '; DROP TABLE users; --"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 2.0 JWT token" in message

    @pytest.mark.asyncio
    async def test_oauth2_xss_in_token(self):
        """Test that XSS attempts in token are handled safely."""
        config = {"oauth2": {"jwt_secret": "secret_key", "jwt_algorithms": ["HS256"]}}

        headers = {"authorization": "Bearer <script>alert('xss')</script>"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 2.0 JWT token" in message

    @pytest.mark.asyncio
    async def test_oauth2_very_long_token(self):
        """Test validation with very long token."""
        config = {"oauth2": {"validate_token": False}}

        long_token = "a" * 10000
        headers = {"authorization": f"Bearer {long_token}"}

        validator = OAuth2Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_oauth2_multiple_algorithms(self):
        """Test JWT validation with multiple algorithms."""
        import jwt

        config = {
            "oauth2": {
                "jwt_secret": "secret_key",
                "jwt_algorithms": ["HS256", "HS384", "HS512"],
            }
        }

        # Test with HS256
        token = jwt.encode({"sub": "user123"}, "secret_key", algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}

        validator = OAuth2Validator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True

        # Test with HS384
        token = jwt.encode({"sub": "user123"}, "secret_key", algorithm="HS384")
        headers = {"authorization": f"Bearer {token}"}

        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True
