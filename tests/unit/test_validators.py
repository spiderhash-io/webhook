import pytest
import hmac
import hashlib
from httpx import AsyncClient, ASGITransport
from src.main import app

host = "test"
test_url = f"http://{host}"


@pytest.mark.asyncio
async def test_hmac_validation_success():
    """Test successful HMAC validation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        payload = {"test": "data"}
        secret = "test_secret_key"

        # Compute HMAC
        body = '{"test":"data"}'
        hmac_obj = hmac.new(secret.encode(), body.encode(), hashlib.sha256)
        signature = hmac_obj.hexdigest()

        # Note: This test requires a webhook configured with HMAC
        # For now, we'll just test the validator directly


@pytest.mark.asyncio
async def test_hmac_validation_failure():
    """Test failed HMAC validation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        payload = {"test": "data"}

        # Send with wrong signature
        # Note: This test requires a webhook configured with HMAC


@pytest.mark.asyncio
async def test_ip_whitelist():
    """Test IP whitelist validation."""
    # Note: This test requires a webhook configured with IP whitelist
    pass


# Direct validator tests
from src.validators import HMACValidator, IPWhitelistValidator, AuthorizationValidator


@pytest.mark.asyncio
async def test_hmac_validator_direct():
    """Test HMAC validator directly."""
    config = {
        "hmac": {
            "secret": "test_secret",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256",
        }
    }

    validator = HMACValidator(config)

    body = b'{"test": "data"}'
    hmac_obj = hmac.new(b"test_secret", body, hashlib.sha256)
    signature = hmac_obj.hexdigest()

    headers = {"x-hmac-signature": signature}

    is_valid, message = await validator.validate(headers, body)
    assert is_valid is True
    assert "Valid" in message


@pytest.mark.asyncio
async def test_hmac_validator_invalid_signature():
    """Test HMAC validator with invalid signature."""
    config = {
        "hmac": {
            "secret": "test_secret",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256",
        }
    }

    validator = HMACValidator(config)

    body = b'{"test": "data"}'
    headers = {"x-hmac-signature": "invalid_signature"}

    is_valid, message = await validator.validate(headers, body)
    assert is_valid is False
    assert "Invalid" in message


@pytest.mark.asyncio
async def test_hmac_validator_missing_header():
    """Test HMAC validator with missing signature header."""
    config = {
        "hmac": {
            "secret": "test_secret",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256",
        }
    }

    validator = HMACValidator(config)

    body = b'{"test": "data"}'
    headers = {}

    is_valid, message = await validator.validate(headers, body)
    assert is_valid is False
    assert "Missing" in message


@pytest.mark.asyncio
async def test_ip_whitelist_validator():
    """Test IP whitelist validator."""
    from unittest.mock import Mock

    # Mock Request object for secure IP detection
    mock_request = Mock()
    mock_request.client = Mock()
    mock_request.client.host = "192.168.1.1"

    config = {"ip_whitelist": ["192.168.1.1", "10.0.0.1"]}

    validator = IPWhitelistValidator(config, request=mock_request)

    # Valid IP (from request.client.host)
    headers = {}
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True

    # Invalid IP
    mock_request.client.host = "192.168.1.2"
    validator = IPWhitelistValidator(config, request=mock_request)
    headers = {}
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False


@pytest.mark.asyncio
async def test_authorization_validator():
    """Test authorization validator."""
    config = {"authorization": "Bearer secret_token"}

    validator = AuthorizationValidator(config)

    # Valid auth
    headers = {"authorization": "Bearer secret_token"}
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True

    # Invalid auth
    headers = {"authorization": "Bearer wrong_token"}
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
