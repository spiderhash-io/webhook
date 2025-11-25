"""
Comprehensive tests for JWT Authentication.
"""
import pytest
import jwt
import time
from src.validators import JWTValidator


# ============================================================================
# JWT VALIDATOR TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_jwt_valid_token():
    """Test valid JWT token."""
    secret = "jwt_secret_key"
    config = {
        "jwt": {
            "secret": secret,
            "algorithm": "HS256"
        }
    }
    
    validator = JWTValidator(config)
    
    # Create valid JWT
    token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True
    assert "Valid JWT" in message


@pytest.mark.asyncio
async def test_jwt_expired_token():
    """Test expired JWT token."""
    secret = "jwt_secret_key"
    config = {
        "jwt": {
            "secret": secret,
            "algorithm": "HS256",
            "verify_exp": True
        }
    }
    
    validator = JWTValidator(config)
    
    # Create expired JWT
    payload = {"exp": time.time() - 3600}  # Expired 1 hour ago
    token = jwt.encode(payload, secret, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "expired" in message


@pytest.mark.asyncio
async def test_jwt_invalid_signature():
    """Test JWT with invalid signature."""
    secret = "jwt_secret_key"
    config = {
        "jwt": {
            "secret": secret,
            "algorithm": "HS256"
        }
    }
    
    validator = JWTValidator(config)
    
    # Sign with different secret
    token = jwt.encode({"user": "test"}, "wrong_secret", algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid JWT signature" in message


@pytest.mark.asyncio
async def test_jwt_wrong_algorithm():
    """Test JWT signed with wrong algorithm."""
    secret = "jwt_secret_key"
    config = {
        "jwt": {
            "secret": secret,
            "algorithm": "HS256"
        }
    }
    
    validator = JWTValidator(config)
    
    # Sign with HS512 but expect HS256
    token = jwt.encode({"user": "test"}, secret, algorithm="HS512")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid JWT algorithm" in message


@pytest.mark.asyncio
async def test_jwt_valid_issuer():
    """Test JWT with valid issuer."""
    secret = "jwt_secret_key"
    issuer = "my-app"
    config = {
        "jwt": {
            "secret": secret,
            "algorithm": "HS256",
            "issuer": issuer
        }
    }
    
    validator = JWTValidator(config)
    
    token = jwt.encode({"iss": issuer}, secret, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True


@pytest.mark.asyncio
async def test_jwt_invalid_issuer():
    """Test JWT with invalid issuer."""
    secret = "jwt_secret_key"
    config = {
        "jwt": {
            "secret": secret,
            "algorithm": "HS256",
            "issuer": "expected-issuer"
        }
    }
    
    validator = JWTValidator(config)
    
    token = jwt.encode({"iss": "wrong-issuer"}, secret, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid JWT issuer" in message


@pytest.mark.asyncio
async def test_jwt_valid_audience():
    """Test JWT with valid audience."""
    secret = "jwt_secret_key"
    audience = "my-api"
    config = {
        "jwt": {
            "secret": secret,
            "algorithm": "HS256",
            "audience": audience
        }
    }
    
    validator = JWTValidator(config)
    
    token = jwt.encode({"aud": audience}, secret, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True


@pytest.mark.asyncio
async def test_jwt_invalid_audience():
    """Test JWT with invalid audience."""
    secret = "jwt_secret_key"
    config = {
        "jwt": {
            "secret": secret,
            "algorithm": "HS256",
            "audience": "expected-audience"
        }
    }
    
    validator = JWTValidator(config)
    
    token = jwt.encode({"aud": "wrong-audience"}, secret, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid JWT audience" in message


@pytest.mark.asyncio
async def test_jwt_missing_header():
    """Test JWT with missing Authorization header."""
    config = {
        "jwt": {
            "secret": "secret"
        }
    }
    
    validator = JWTValidator(config)
    
    headers = {}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Missing Authorization header" in message


@pytest.mark.asyncio
async def test_jwt_wrong_scheme():
    """Test JWT with wrong auth scheme."""
    config = {
        "jwt": {
            "secret": "secret"
        }
    }
    
    validator = JWTValidator(config)
    
    headers = {"authorization": "Basic user:pass"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "JWT Bearer token required" in message


@pytest.mark.asyncio
async def test_jwt_malformed_token():
    """Test JWT with malformed token string."""
    config = {
        "jwt": {
            "secret": "secret"
        }
    }
    
    validator = JWTValidator(config)
    
    headers = {"authorization": "Bearer invalid.token.string"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "Invalid JWT token format" in message


@pytest.mark.asyncio
async def test_jwt_no_config():
    """Test JWT when not configured."""
    config = {}
    
    validator = JWTValidator(config)
    
    headers = {}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True
    assert "No JWT validation required" in message


@pytest.mark.asyncio
async def test_jwt_missing_claims_when_required():
    """Test JWT missing required claims (iss/aud)."""
    secret = "jwt_secret_key"
    config = {
        "jwt": {
            "secret": secret,
            "issuer": "required-issuer"
        }
    }
    
    validator = JWTValidator(config)
    
    # Token without 'iss' claim
    token = jwt.encode({"data": "test"}, secret, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is False
    assert "JWT missing required claim" in message


@pytest.mark.asyncio
async def test_jwt_future_expiration():
    """Test JWT with future expiration (valid)."""
    secret = "jwt_secret_key"
    config = {
        "jwt": {
            "secret": secret,
            "verify_exp": True
        }
    }
    
    validator = JWTValidator(config)
    
    # Expire in 1 hour
    payload = {"exp": time.time() + 3600}
    token = jwt.encode(payload, secret, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    
    is_valid, message = await validator.validate(headers, b"")
    assert is_valid is True
