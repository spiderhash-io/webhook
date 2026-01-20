"""
Tests for Google reCAPTCHA validation.
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from src.validators import RecaptchaValidator


@pytest.mark.asyncio
async def test_recaptcha_no_config():
    """Test reCAPTCHA validator with no configuration."""
    config = {}
    validator = RecaptchaValidator(config)

    headers = {}
    body = b'{"test": "data"}'

    is_valid, message = await validator.validate(headers, body)
    assert is_valid is True
    assert "No reCAPTCHA validation required" in message


@pytest.mark.asyncio
async def test_recaptcha_missing_secret_key():
    """Test reCAPTCHA validator with missing secret key."""
    config = {"recaptcha": {"version": "v3"}}
    validator = RecaptchaValidator(config)

    headers = {"x-recaptcha-token": "test_token"}
    body = b'{"test": "data"}'

    is_valid, message = await validator.validate(headers, body)
    assert is_valid is False
    assert "secret key not configured" in message


@pytest.mark.asyncio
async def test_recaptcha_missing_token_header():
    """Test reCAPTCHA validator with missing token in header."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v3",
            "token_source": "header",
            "token_field": "X-Recaptcha-Token",
        }
    }
    validator = RecaptchaValidator(config)

    headers = {}
    body = b'{"test": "data"}'

    is_valid, message = await validator.validate(headers, body)
    assert is_valid is False
    assert "Missing reCAPTCHA token" in message


@pytest.mark.asyncio
async def test_recaptcha_missing_token_body():
    """Test reCAPTCHA validator with missing token in body."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v3",
            "token_source": "body",
            "token_field": "recaptcha_token",
        }
    }
    validator = RecaptchaValidator(config)

    headers = {}
    body = b'{"test": "data"}'

    is_valid, message = await validator.validate(headers, body)
    assert is_valid is False
    assert "Missing reCAPTCHA token" in message


@pytest.mark.asyncio
async def test_recaptcha_v3_success():
    """Test successful reCAPTCHA v3 validation."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v3",
            "token_source": "header",
            "token_field": "X-Recaptcha-Token",
            "min_score": 0.5,
        }
    }
    validator = RecaptchaValidator(config)

    headers = {"x-recaptcha-token": "valid_token"}
    body = b'{"test": "data"}'

    # Mock successful Google API response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "success": True,
        "score": 0.9,
        "action": "submit",
        "challenge_ts": "2023-01-01T00:00:00Z",
    }
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.return_value = mock_response

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True
        assert "Valid reCAPTCHA token" in message
        assert "score" in message.lower()


@pytest.mark.asyncio
async def test_recaptcha_v3_low_score():
    """Test reCAPTCHA v3 validation with score below threshold."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v3",
            "token_source": "header",
            "token_field": "X-Recaptcha-Token",
            "min_score": 0.7,
        }
    }
    validator = RecaptchaValidator(config)

    headers = {"x-recaptcha-token": "valid_token"}
    body = b'{"test": "data"}'

    # Mock Google API response with low score
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "success": True,
        "score": 0.3,  # Below threshold of 0.7
        "action": "submit",
    }
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.return_value = mock_response

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is False
        assert "below threshold" in message.lower()


@pytest.mark.asyncio
async def test_recaptcha_v2_success():
    """Test successful reCAPTCHA v2 validation."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v2",
            "token_source": "body",
            "token_field": "g-recaptcha-response",
        }
    }
    validator = RecaptchaValidator(config)

    headers = {}
    body = json.dumps({"g-recaptcha-response": "valid_token"}).encode()

    # Mock successful Google API response
    mock_response = MagicMock()
    mock_response.json.return_value = {"success": True}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.return_value = mock_response

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True
        assert "Valid reCAPTCHA token" in message


@pytest.mark.asyncio
async def test_recaptcha_verification_failed():
    """Test reCAPTCHA validation with failed verification."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v3",
            "token_source": "header",
            "token_field": "X-Recaptcha-Token",
        }
    }
    validator = RecaptchaValidator(config)

    headers = {"x-recaptcha-token": "invalid_token"}
    body = b'{"test": "data"}'

    # Mock failed Google API response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "success": False,
        "error-codes": ["invalid-input-response", "timeout-or-duplicate"],
    }
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.return_value = mock_response

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is False
        assert "verification failed" in message.lower()
        assert "invalid-input-response" in message or "timeout-or-duplicate" in message


@pytest.mark.asyncio
async def test_recaptcha_token_from_body_custom_field():
    """Test reCAPTCHA token extraction from body with custom field."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v3",
            "token_source": "body",
            "token_field": "recaptcha_token",
        }
    }
    validator = RecaptchaValidator(config)

    headers = {}
    body = json.dumps({"recaptcha_token": "test_token"}).encode()

    # Mock successful response
    mock_response = MagicMock()
    mock_response.json.return_value = {"success": True, "score": 0.8}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.return_value = mock_response

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True


@pytest.mark.asyncio
async def test_recaptcha_http_error():
    """Test reCAPTCHA validator with HTTP error."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v3",
            "token_source": "header",
            "token_field": "X-Recaptcha-Token",
        }
    }
    validator = RecaptchaValidator(config)

    headers = {"x-recaptcha-token": "test_token"}
    body = b'{"test": "data"}'

    # Mock HTTP error
    with patch("httpx.AsyncClient") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.side_effect = Exception("Connection error")

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is False
        assert "error" in message.lower()


@pytest.mark.asyncio
async def test_recaptcha_with_client_ip():
    """Test reCAPTCHA validation includes client IP for v3."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret",
            "version": "v3",
            "token_source": "header",
            "token_field": "X-Recaptcha-Token",
        }
    }
    validator = RecaptchaValidator(config)

    headers = {"x-recaptcha-token": "test_token", "x-forwarded-for": "192.168.1.100"}
    body = b'{"test": "data"}'

    # Mock successful response
    mock_response = MagicMock()
    mock_response.json.return_value = {"success": True, "score": 0.8}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.return_value = mock_response

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True

        # Verify that remoteip was included in the request
        call_args = mock_client_instance.post.call_args
        assert call_args is not None
        # The data should include remoteip
        data = call_args[1]["data"]
        assert "remoteip" in data
        assert data["remoteip"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_recaptcha_default_values():
    """Test reCAPTCHA validator with default configuration values."""
    config = {
        "recaptcha": {
            "secret_key": "test_secret"
            # version defaults to v3
            # token_source defaults to header
            # token_field defaults to X-Recaptcha-Token
            # min_score defaults to 0.5
        }
    }
    validator = RecaptchaValidator(config)

    assert validator.version == "v3"
    assert validator.token_source == "header"
    assert validator.token_field == "X-Recaptcha-Token"
    assert validator.min_score == 0.5

    headers = {"x-recaptcha-token": "test_token"}
    body = b'{"test": "data"}'

    # Mock successful response
    mock_response = MagicMock()
    mock_response.json.return_value = {"success": True, "score": 0.6}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        mock_client_instance.post.return_value = mock_response

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True
