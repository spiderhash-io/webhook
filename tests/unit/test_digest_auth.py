"""
Tests for HTTP Digest Authentication validator.
Includes security edge cases and comprehensive validation.
"""

import pytest
import hashlib
from src.validators import DigestAuthValidator


def generate_digest_response(
    username: str,
    password: str,
    realm: str,
    method: str,
    uri: str,
    nonce: str,
    nc: str = "00000001",
    cnonce: str = "",
    qop: str = "auth",
) -> str:
    """Helper function to generate valid Digest response."""
    # HA1 = MD5(username:realm:password)
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()

    # HA2 = MD5(method:uri)
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

    # Response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
    if qop == "auth" and cnonce:
        response_str = f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"
    else:
        response_str = f"{ha1}:{nonce}:{ha2}"

    return hashlib.md5(response_str.encode()).hexdigest()


class TestDigestAuth:
    """Test suite for HTTP Digest Authentication."""

    @pytest.mark.asyncio
    async def test_digest_auth_no_config(self):
        """Test that validation passes when no digest auth is configured."""
        config = {}
        validator = DigestAuthValidator(config)

        headers = {}
        body = b"test"

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True
        assert "No digest auth required" in message

    @pytest.mark.asyncio
    async def test_digest_auth_missing_authorization_header(self):
        """Test validation when Authorization header is missing."""
        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass",
                "realm": "Test Realm",
            }
        }

        headers = {}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Missing Authorization header" in message

    @pytest.mark.asyncio
    async def test_digest_auth_wrong_scheme(self):
        """Test validation with wrong authentication scheme."""
        config = {"digest_auth": {"username": "user", "password": "pass"}}

        headers = {"authorization": "Basic dXNlcjpwYXNz"}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Digest authentication required" in message

    @pytest.mark.asyncio
    async def test_digest_auth_valid_credentials(self):
        """Test validation with valid credentials."""
        config = {
            "digest_auth": {
                "username": "testuser",
                "password": "testpass",
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"
        method = "POST"

        response = generate_digest_response(
            "testuser", "testpass", "Test Realm", method, uri, nonce, nc, cnonce
        )

        auth_header = (
            f'Digest username="testuser", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'algorithm=MD5, response="{response}", '
            f'qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
        assert "Valid digest authentication" in message

    @pytest.mark.asyncio
    async def test_digest_auth_invalid_password(self):
        """Test validation with invalid password."""
        config = {
            "digest_auth": {
                "username": "testuser",
                "password": "testpass",
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        # Use wrong password
        response = generate_digest_response(
            "testuser", "wrongpass", "Test Realm", "POST", uri, nonce, nc, cnonce
        )

        auth_header = (
            f'Digest username="testuser", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid digest auth response" in message

    @pytest.mark.asyncio
    async def test_digest_auth_invalid_username(self):
        """Test validation with invalid username."""
        config = {
            "digest_auth": {
                "username": "testuser",
                "password": "testpass",
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        response = generate_digest_response(
            "wronguser", "testpass", "Test Realm", "POST", uri, nonce, nc, cnonce
        )

        auth_header = (
            f'Digest username="wronguser", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid digest auth username" in message

    @pytest.mark.asyncio
    async def test_digest_auth_invalid_realm(self):
        """Test validation with invalid realm."""
        config = {
            "digest_auth": {
                "username": "testuser",
                "password": "testpass",
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        response = generate_digest_response(
            "testuser", "testpass", "Wrong Realm", "POST", uri, nonce, nc, cnonce
        )

        auth_header = (
            f'Digest username="testuser", realm="Wrong Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid digest auth realm" in message

    @pytest.mark.asyncio
    async def test_digest_auth_missing_username_config(self):
        """Test validation when username is not configured."""
        config = {"digest_auth": {"password": "testpass"}}

        headers = {"authorization": 'Digest username="testuser"'}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Digest auth credentials not configured" in message

    @pytest.mark.asyncio
    async def test_digest_auth_missing_password_config(self):
        """Test validation when password is not configured."""
        config = {"digest_auth": {"username": "testuser"}}

        headers = {"authorization": 'Digest username="testuser"'}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Digest auth credentials not configured" in message

    @pytest.mark.asyncio
    async def test_digest_auth_missing_required_parameter(self):
        """Test validation when required parameter is missing."""
        config = {
            "digest_auth": {
                "username": "testuser",
                "password": "testpass",
                "realm": "Test Realm",
            }
        }

        # Missing nonce
        auth_header = (
            'Digest username="testuser", realm="Test Realm", uri="/webhook/test"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Missing required Digest parameter" in message

    @pytest.mark.asyncio
    async def test_digest_auth_custom_realm(self):
        """Test validation with custom realm."""
        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass",
                "realm": "Custom Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        response = generate_digest_response(
            "user", "pass", "Custom Realm", "POST", uri, nonce, nc, cnonce
        )

        auth_header = (
            f'Digest username="user", realm="Custom Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_digest_auth_no_qop(self):
        """Test validation without qop (quality of protection)."""
        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass",
                "realm": "Test Realm",
                "qop": "",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        uri = "/webhook/test"

        # Generate response without qop
        ha1 = hashlib.md5("user:Test Realm:pass".encode()).hexdigest()
        ha2 = hashlib.md5("POST:/webhook/test".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

        auth_header = (
            f'Digest username="user", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_digest_auth_special_characters_in_credentials(self):
        """Test validation with special characters in username/password."""
        config = {
            "digest_auth": {
                "username": "user@domain.com",
                "password": "p@ss:w0rd!",
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        response = generate_digest_response(
            "user@domain.com",
            "p@ss:w0rd!",
            "Test Realm",
            "POST",
            uri,
            nonce,
            nc,
            cnonce,
        )

        auth_header = (
            f'Digest username="user@domain.com", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_digest_auth_unicode_credentials(self):
        """Test validation with Unicode characters in credentials."""
        config = {
            "digest_auth": {"username": "用户", "password": "密码", "realm": "测试领域"}
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        response = generate_digest_response(
            "用户", "密码", "测试领域", "POST", uri, nonce, nc, cnonce
        )

        auth_header = (
            f'Digest username="用户", realm="测试领域", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_digest_auth_timing_attack_resistance(self):
        """Test that validation uses constant-time comparison to resist timing attacks."""
        import time

        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass",
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        # Correct response
        correct_response = generate_digest_response(
            "user", "pass", "Test Realm", "POST", uri, nonce, nc, cnonce
        )

        correct_header = (
            f'Digest username="user", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{correct_response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        # Wrong response (first character different)
        wrong_response = "x" + correct_response[1:]
        wrong_header = (
            f'Digest username="user", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{wrong_response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        validator = DigestAuthValidator(config)

        # Measure time for correct response
        correct_times = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate({"authorization": correct_header}, body=b"test")
            correct_times.append(time.perf_counter() - start)
        correct_time = sum(correct_times) / len(correct_times)

        # Measure time for wrong response
        wrong_times = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate({"authorization": wrong_header}, body=b"test")
            wrong_times.append(time.perf_counter() - start)
        wrong_time = sum(wrong_times) / len(wrong_times)

        # Times should be similar (within reasonable margin)
        time_diff_ratio = abs(correct_time - wrong_time) / max(
            correct_time, wrong_time, 0.000001
        )

        # Allow up to 70% difference due to system noise
        assert (
            time_diff_ratio < 0.7
        ), f"Timing attack vulnerability detected: {time_diff_ratio:.2%}"

    @pytest.mark.asyncio
    async def test_digest_auth_malformed_header(self):
        """Test validation with malformed Digest header."""
        config = {"digest_auth": {"username": "user", "password": "pass"}}

        # Malformed header (missing quotes, etc.)
        headers = {"authorization": "Digest username=user, realm=Test"}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_digest_auth_sql_injection_attempt(self):
        """Test that SQL injection attempts are handled safely."""
        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass",
                "realm": "Test Realm",
            }
        }

        # Attempt SQL injection in username - username check should fail first
        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        # Use SQL injection username in header (will fail username check)
        auth_header = (
            f'Digest username="user\'; DROP TABLE users; --", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="invalid", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        # Should fail at username validation (username doesn't match)
        assert (
            "Invalid digest auth username" in message
            or "Invalid digest auth response" in message
        )

    @pytest.mark.asyncio
    async def test_digest_auth_xss_attempt(self):
        """Test that XSS attempts are handled safely."""
        config = {"digest_auth": {"username": "user", "password": "pass"}}

        headers = {"authorization": "Digest username=\"<script>alert('xss')</script>\""}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_digest_auth_empty_config(self):
        """Test validation when digest_auth config exists but is empty."""
        config = {"digest_auth": {}}

        headers = {"authorization": 'Digest username="user"'}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Digest auth credentials not configured" in message

    @pytest.mark.asyncio
    async def test_digest_auth_different_uri(self):
        """Test validation with different URI (should fail)."""
        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass",
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        # Generate response for correct URI
        response = generate_digest_response(
            "user", "pass", "Test Realm", "POST", uri, nonce, nc, cnonce
        )

        # But use different URI in header
        auth_header = (
            f'Digest username="user", realm="Test Realm", '
            f'nonce="{nonce}", uri="/webhook/different", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid digest auth response" in message

    @pytest.mark.asyncio
    async def test_digest_auth_different_method(self):
        """Test validation with different HTTP method (should fail)."""
        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass",
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        # Generate response for GET (but we're using POST)
        response = generate_digest_response(
            "user", "pass", "Test Realm", "GET", uri, nonce, nc, cnonce
        )

        auth_header = (
            f'Digest username="user", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid digest auth response" in message

    @pytest.mark.asyncio
    async def test_digest_auth_algorithm_validation(self):
        """Test validation with algorithm parameter."""
        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass",
                "realm": "Test Realm",
                "algorithm": "MD5",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        response = generate_digest_response(
            "user", "pass", "Test Realm", "POST", uri, nonce, nc, cnonce
        )

        # Correct algorithm
        auth_header = (
            f'Digest username="user", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'algorithm=MD5, response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}
        validator = DigestAuthValidator(config)
        is_valid, _ = await validator.validate(headers, body=b"test")
        assert is_valid is True

        # Wrong algorithm
        auth_header = (
            f'Digest username="user", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'algorithm=SHA256, response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid digest auth algorithm" in message

    @pytest.mark.asyncio
    async def test_digest_auth_long_credentials(self):
        """Test validation with very long credentials."""
        long_username = "a" * 1000
        long_password = "b" * 1000

        config = {
            "digest_auth": {
                "username": long_username,
                "password": long_password,
                "realm": "Test Realm",
            }
        }

        nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
        nc = "00000001"
        cnonce = "0a4f113b"
        uri = "/webhook/test"

        response = generate_digest_response(
            long_username, long_password, "Test Realm", "POST", uri, nonce, nc, cnonce
        )

        auth_header = (
            f'Digest username="{long_username}", realm="Test Realm", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

        headers = {"authorization": auth_header}

        validator = DigestAuthValidator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
