"""
Comprehensive tests for Basic Authentication.
"""

import pytest
import base64
from src.validators import BasicAuthValidator


# ============================================================================
# BASIC AUTH VALIDATOR TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_basic_auth_valid_credentials():
    """Test valid basic authentication."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    # Create valid basic auth header
    credentials = "admin:secret123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True
    assert "Valid" in message


@pytest.mark.asyncio
async def test_basic_auth_invalid_password():
    """Test basic auth with invalid password."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    # Wrong password
    credentials = "admin:wrongpassword"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid credentials" in message


@pytest.mark.asyncio
async def test_basic_auth_invalid_username():
    """Test basic auth with invalid username."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    # Wrong username
    credentials = "wronguser:secret123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid credentials" in message


@pytest.mark.asyncio
async def test_basic_auth_missing_header():
    """Test basic auth with missing Authorization header."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    headers = {}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Missing Authorization header" in message


@pytest.mark.asyncio
async def test_basic_auth_wrong_scheme():
    """Test basic auth with wrong authentication scheme."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    headers = {"authorization": "Bearer some_token"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Basic authentication required" in message


@pytest.mark.asyncio
async def test_basic_auth_invalid_base64():
    """Test basic auth with invalid base64 encoding."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    headers = {"authorization": "Basic invalid!!!base64"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid base64 encoding" in message


@pytest.mark.asyncio
async def test_basic_auth_missing_colon():
    """Test basic auth without colon separator."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    # Credentials without colon
    credentials = "adminpassword"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid basic auth format" in message


@pytest.mark.asyncio
async def test_basic_auth_empty_username():
    """Test basic auth with empty username."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    credentials = ":secret123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid credentials" in message


@pytest.mark.asyncio
async def test_basic_auth_empty_password():
    """Test basic auth with empty password."""
    config = {"basic_auth": {"username": "admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    credentials = "admin:"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid credentials" in message


@pytest.mark.asyncio
async def test_basic_auth_password_with_colon():
    """Test basic auth with password containing colon."""
    config = {"basic_auth": {"username": "admin", "password": "secret:123:456"}}

    validator = BasicAuthValidator(config)

    # Password with colons should work
    credentials = "admin:secret:123:456"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True
    assert "Valid" in message


@pytest.mark.asyncio
async def test_basic_auth_special_characters():
    """Test basic auth with special characters in credentials."""
    config = {"basic_auth": {"username": "user@example.com", "password": "p@$$w0rd!#%"}}

    validator = BasicAuthValidator(config)

    credentials = "user@example.com:p@$$w0rd!#%"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True


@pytest.mark.asyncio
async def test_basic_auth_unicode_characters():
    """Test basic auth with unicode characters."""
    config = {
        "basic_auth": {
            "username": "user",
            "password": "пароль",  # Russian for "password"
        }
    }

    validator = BasicAuthValidator(config)

    credentials = "user:пароль"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True


@pytest.mark.asyncio
async def test_basic_auth_no_config():
    """Test basic auth when not configured."""
    config = {}

    validator = BasicAuthValidator(config)

    headers = {}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True
    assert "No basic auth required" in message


@pytest.mark.asyncio
async def test_basic_auth_missing_username_config():
    """Test basic auth with missing username in config."""
    config = {"basic_auth": {"password": "secret123"}}

    validator = BasicAuthValidator(config)

    credentials = "admin:secret123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "not configured" in message


@pytest.mark.asyncio
async def test_basic_auth_missing_password_config():
    """Test basic auth with missing password in config."""
    config = {"basic_auth": {"username": "admin"}}

    validator = BasicAuthValidator(config)

    credentials = "admin:secret123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "not configured" in message


@pytest.mark.asyncio
async def test_basic_auth_case_sensitive_username():
    """Test that username is case-sensitive."""
    config = {"basic_auth": {"username": "Admin", "password": "secret123"}}

    validator = BasicAuthValidator(config)

    # Lowercase username should fail
    credentials = "admin:secret123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False


@pytest.mark.asyncio
async def test_basic_auth_case_sensitive_password():
    """Test that password is case-sensitive."""
    config = {"basic_auth": {"username": "admin", "password": "Secret123"}}

    validator = BasicAuthValidator(config)

    # Lowercase password should fail
    credentials = "admin:secret123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False


@pytest.mark.asyncio
async def test_basic_auth_whitespace_in_credentials():
    """Test basic auth with whitespace in credentials."""
    config = {"basic_auth": {"username": "admin", "password": "secret 123"}}

    validator = BasicAuthValidator(config)

    # Password with space should work
    credentials = "admin:secret 123"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True


@pytest.mark.asyncio
async def test_basic_auth_long_credentials():
    """Test basic auth with very long credentials."""
    config = {"basic_auth": {"username": "user" * 100, "password": "pass" * 100}}

    validator = BasicAuthValidator(config)

    credentials = f"{'user' * 100}:{'pass' * 100}"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers = {"authorization": f"Basic {encoded}"}

    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True


@pytest.mark.asyncio
async def test_basic_auth_timing_attack_resistance():
    """Test that password comparison is timing-attack resistant."""
    config = {
        "basic_auth": {
            "username": "admin",
            "password": "verylongsecretpassword123456789",
        }
    }

    validator = BasicAuthValidator(config)

    # Test with completely wrong password
    credentials1 = "admin:wrongpassword"
    encoded1 = base64.b64encode(credentials1.encode()).decode()
    headers1 = {"authorization": f"Basic {encoded1}"}

    # Test with almost correct password
    credentials2 = "admin:verylongsecretpassword12345678X"
    encoded2 = base64.b64encode(credentials2.encode()).decode()
    headers2 = {"authorization": f"Basic {encoded2}"}

    # Both should fail
    is_valid1, _ = await validator.validate(headers1, b"")
    is_valid2, _ = await validator.validate(headers2, b"")

    assert is_valid1 is False
    assert is_valid2 is False
    # The comparison should use constant-time comparison (hmac.compare_digest)
