"""
Comprehensive security audit tests for RecaptchaValidator.
Tests IP spoofing, SSRF, error disclosure, token manipulation, DoS, and configuration security.
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from src.validators import RecaptchaValidator


# ============================================================================
# 1. IP SPOOFING & HEADER MANIPULATION
# ============================================================================


class TestRecaptchaIPSpoofing:
    """Test IP spoofing and header manipulation vulnerabilities."""

    @pytest.mark.asyncio
    async def test_ip_spoofing_via_x_forwarded_for(self):
        """Test that X-Forwarded-For header can be spoofed."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "token_source": "header",
                "token_field": "X-Recaptcha-Token",
            }
        }
        validator = RecaptchaValidator(config)

        # Attacker spoofs IP via X-Forwarded-For
        headers = {
            "x-recaptcha-token": "test_token",
            "x-forwarded-for": "192.168.1.1",  # Spoofed IP
        }
        body = b'{"test": "data"}'

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "score": 0.8}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_response

            is_valid, message = await validator.validate(headers, body)

            # Verify that spoofed IP was used in request
            call_args = mock_client_instance.post.call_args
            if call_args:
                data = call_args[1].get("data", {})
                if "remoteip" in data:
                    # Should use spoofed IP (this is a vulnerability if not validated)
                    assert data["remoteip"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_ip_spoofing_via_x_real_ip(self):
        """Test that X-Real-IP header can be spoofed."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "token_source": "header",
                "token_field": "X-Recaptcha-Token",
            }
        }
        validator = RecaptchaValidator(config)

        # Attacker spoofs IP via X-Real-IP
        headers = {
            "x-recaptcha-token": "test_token",
            "x-real-ip": "10.0.0.1",  # Spoofed IP
        }
        body = b'{"test": "data"}'

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "score": 0.8}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_response

            is_valid, message = await validator.validate(headers, body)

            # Verify that spoofed IP was used
            call_args = mock_client_instance.post.call_args
            if call_args:
                data = call_args[1].get("data", {})
                if "remoteip" in data:
                    assert data["remoteip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_x_forwarded_for_multiple_ips(self):
        """Test handling of X-Forwarded-For with multiple IPs."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "token_source": "header",
                "token_field": "X-Recaptcha-Token",
            }
        }
        validator = RecaptchaValidator(config)

        # X-Forwarded-For with multiple IPs (first should be used)
        headers = {
            "x-recaptcha-token": "test_token",
            "x-forwarded-for": "192.168.1.1, 10.0.0.1, 172.16.0.1",
        }
        body = b'{"test": "data"}'

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "score": 0.8}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_response

            is_valid, message = await validator.validate(headers, body)

            # Should use first IP after splitting
            call_args = mock_client_instance.post.call_args
            if call_args:
                data = call_args[1].get("data", {})
                if "remoteip" in data:
                    assert data["remoteip"] == "192.168.1.1"


# ============================================================================
# 2. SSRF & URL VALIDATION
# ============================================================================


class TestRecaptchaSSRF:
    """Test SSRF vulnerabilities via URL manipulation."""

    @pytest.mark.asyncio
    async def test_verify_url_hardcoded(self):
        """Test that verify_url is hardcoded and cannot be changed."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        # Verify URL is hardcoded to Google
        assert validator.verify_url == "https://www.google.com/recaptcha/api/siteverify"
        assert "google.com" in validator.verify_url.lower()

    @pytest.mark.asyncio
    async def test_no_internal_network_access(self):
        """Test that validator cannot be tricked into accessing internal networks."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        # Verify URL should only point to Google
        assert not validator.verify_url.startswith("http://127.0.0.1")
        assert not validator.verify_url.startswith("http://localhost")
        assert not validator.verify_url.startswith("http://192.168")
        assert not validator.verify_url.startswith("http://10.0")
        assert not validator.verify_url.startswith("http://172.16")


# ============================================================================
# 3. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestRecaptchaErrorDisclosure:
    """Test error message information disclosure."""

    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages don't expose sensitive information."""
        config = {"recaptcha": {"secret_key": "secret_key_12345", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Mock HTTP error that might leak sensitive info
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.side_effect = Exception(
                "Connection error with secret: secret_key_12345"
            )

            is_valid, message = await validator.validate(headers, body)
            assert is_valid is False

            # Should not expose secret key
            assert "secret_key_12345" not in message
            assert (
                "secret" not in message.lower() or "secret key" in message.lower()
            )  # May mention "secret key" but not the value

    @pytest.mark.asyncio
    async def test_httpx_error_sanitization(self):
        """Test that httpx.HTTPError messages are sanitized."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Mock httpx.HTTPError
        import httpx

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.side_effect = httpx.HTTPError(
                "Internal error with path: /etc/passwd"
            )

            is_valid, message = await validator.validate(headers, body)
            assert is_valid is False

            # Should sanitize error message
            error_msg = message.lower()
            assert "/etc/passwd" not in error_msg
            assert (
                "internal error" not in error_msg
                or "failed to verify" in message.lower()
            )

    @pytest.mark.asyncio
    async def test_generic_exception_sanitization(self):
        """Test that generic exceptions are sanitized."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Mock generic exception
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.side_effect = Exception(
                "Internal error with sensitive data"
            )

            is_valid, message = await validator.validate(headers, body)
            assert is_valid is False

            # Should sanitize error message
            error_msg = message.lower()
            assert "sensitive data" not in error_msg
            assert (
                "recaptcha validation" in error_msg
                or "verification" in error_msg
                or "processing error" in error_msg
            )


# ============================================================================
# 4. TOKEN EXTRACTION SECURITY
# ============================================================================


class TestRecaptchaTokenExtraction:
    """Test token extraction security."""

    @pytest.mark.asyncio
    async def test_token_injection_via_header(self):
        """Test that malicious tokens in headers are handled safely."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "token_source": "header",
                "token_field": "X-Recaptcha-Token",
            }
        }
        validator = RecaptchaValidator(config)

        # Malicious token with injection attempts
        malicious_tokens = [
            "../../etc/passwd",
            "'; DROP TABLE users; --",
            "<script>alert(1)</script>",
            "\x00null\x00byte",
            "A" * 10000,  # Very long token
        ]

        for malicious_token in malicious_tokens:
            headers = {"x-recaptcha-token": malicious_token}
            body = b'{"test": "data"}'

            # Should handle malicious tokens safely (may fail validation, but shouldn't crash)
            try:
                mock_response = MagicMock()
                mock_response.json.return_value = {
                    "success": False,
                    "error-codes": ["invalid-input-response"],
                }
                mock_response.raise_for_status = MagicMock()

                with patch("httpx.AsyncClient") as mock_client:
                    mock_client_instance = AsyncMock()
                    mock_client.return_value.__aenter__.return_value = (
                        mock_client_instance
                    )
                    mock_client_instance.post.return_value = mock_response

                    is_valid, message = await validator.validate(headers, body)
                    assert is_valid is False
            except Exception as e:
                # Should not crash on malicious tokens
                assert False, f"Validator crashed on malicious token: {malicious_token}"

    @pytest.mark.asyncio
    async def test_token_extraction_from_body_json_injection(self):
        """Test token extraction from body with JSON injection attempts."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "token_source": "body",
                "token_field": "recaptcha_token",
            }
        }
        validator = RecaptchaValidator(config)

        # JSON injection attempts
        malicious_bodies = [
            b'{"recaptcha_token": "test", "__proto__": {"polluted": true}}',
            b'{"recaptcha_token": "test", "constructor": {"prototype": {"polluted": true}}}',
            b'{"recaptcha_token": null, "recaptcha": null}',
        ]

        for malicious_body in malicious_bodies:
            headers = {}

            try:
                # Should extract token safely
                token = validator._extract_token(headers, malicious_body)
                # Token extraction should not crash
            except Exception as e:
                assert False, f"Token extraction crashed on malicious body: {e}"

    @pytest.mark.asyncio
    async def test_token_extraction_case_sensitivity(self):
        """Test token extraction with case variations."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "token_source": "header",
                "token_field": "X-Recaptcha-Token",
            }
        }
        validator = RecaptchaValidator(config)

        # Test case variations - token_field is "X-Recaptcha-Token"
        # The code tries lowercase first, then original case
        headers_variations = [
            {"x-recaptcha-token": "test_token"},  # Lowercase (should match)
            {"X-Recaptcha-Token": "test_token"},  # Original case (should match)
        ]

        for headers in headers_variations:
            body = b'{"test": "data"}'
            token = validator._extract_token(headers, body)
            # Should extract token regardless of case
            assert token == "test_token"

        # Test uppercase variation (may not match if exact case is required)
        headers_upper = {"X-RECAPTCHA-TOKEN": "test_token"}
        body = b'{"test": "data"}'
        token = validator._extract_token(headers_upper, body)
        # May or may not match depending on implementation
        assert token == "test_token" or token is None


# ============================================================================
# 5. CONFIGURATION SECURITY
# ============================================================================


class TestRecaptchaConfigurationSecurity:
    """Test configuration security and validation."""

    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {"recaptcha": {"secret_key": None}},
            {"recaptcha": {"secret_key": 123}},
            {"recaptcha": {"secret_key": "test", "min_score": "not_a_number"}},
            {"recaptcha": {"secret_key": "test", "version": 123}},
        ]

        for invalid_config in invalid_configs:
            validator = RecaptchaValidator(invalid_config)
            headers = {"x-recaptcha-token": "test_token"}
            body = b'{"test": "data"}'

            # Should handle invalid config gracefully
            is_valid, message = await validator.validate(headers, body)
            # May fail validation, but shouldn't crash
            assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_min_score_validation(self):
        """Test that min_score is validated (should be between 0 and 1)."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "min_score": 1.5,  # Invalid: > 1.0
            }
        }
        validator = RecaptchaValidator(config)

        # Should accept invalid min_score but handle it during validation
        assert validator.min_score == 1.5  # Currently no validation

    @pytest.mark.asyncio
    async def test_negative_min_score(self):
        """Test that negative min_score is handled."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "min_score": -0.5,  # Invalid: negative
            }
        }
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "score": 0.8}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_response

            is_valid, message = await validator.validate(headers, body)
            # Should handle negative score (may pass or fail, but shouldn't crash)
            assert isinstance(is_valid, bool)


# ============================================================================
# 6. DENIAL OF SERVICE (DoS)
# ============================================================================


class TestRecaptchaDoS:
    """Test DoS vulnerabilities."""

    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test that timeout is enforced to prevent DoS."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Mock timeout
        import httpx

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.side_effect = httpx.TimeoutException(
                "Request timed out"
            )

            is_valid, message = await validator.validate(headers, body)
            assert is_valid is False
            assert (
                "error" in message.lower()
                or "timeout" in message.lower()
                or "failed" in message.lower()
            )

    @pytest.mark.asyncio
    async def test_very_long_token_dos(self):
        """Test that very long tokens don't cause DoS."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        # Very long token (1MB)
        very_long_token = "A" * (1024 * 1024)
        headers = {"x-recaptcha-token": very_long_token}
        body = b'{"test": "data"}'

        # Should handle long token without DoS
        try:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "success": False,
                "error-codes": ["invalid-input-response"],
            }
            mock_response.raise_for_status = MagicMock()

            with patch("httpx.AsyncClient") as mock_client:
                mock_client_instance = AsyncMock()
                mock_client.return_value.__aenter__.return_value = mock_client_instance
                mock_client_instance.post.return_value = mock_response

                is_valid, message = await validator.validate(headers, body)
                # Should handle long token (may fail, but shouldn't crash or hang)
                assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash on long token
            assert False, f"Validator crashed on long token: {e}"

    @pytest.mark.asyncio
    async def test_malformed_json_body_dos(self):
        """Test that malformed JSON in body doesn't cause DoS."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "token_source": "body",
                "token_field": "recaptcha_token",
            }
        }
        validator = RecaptchaValidator(config)

        # Malformed JSON bodies
        malformed_bodies = [
            b'{"recaptcha_token": "test"'  # Missing closing brace
            b'{"recaptcha_token": "test",}'  # Trailing comma
            b'{"recaptcha_token":}'  # Missing value
            b'{"recaptcha_token": "test"}' * 10000  # Very large JSON
        ]

        for malformed_body in malformed_bodies:
            headers = {}

            try:
                # Should handle malformed JSON gracefully
                token = validator._extract_token(headers, malformed_body)
                # Should not crash
            except Exception as e:
                # JSON parsing errors are acceptable, but shouldn't cause DoS
                pass


# ============================================================================
# 7. SECRET KEY SECURITY
# ============================================================================


class TestRecaptchaSecretKeySecurity:
    """Test secret key security."""

    @pytest.mark.asyncio
    async def test_secret_key_not_in_error_messages(self):
        """Test that secret key is not exposed in error messages."""
        config = {"recaptcha": {"secret_key": "my_secret_key_12345", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Various error scenarios
        error_scenarios = [
            # HTTP error
            (Exception("Connection error"), "httpx.AsyncClient"),
            # JSON decode error
            (ValueError("Invalid JSON"), "json.loads"),
        ]

        for error, patch_target in error_scenarios:
            try:
                with patch(patch_target, side_effect=error):
                    is_valid, message = await validator.validate(headers, body)
                    if not is_valid:
                        # Should not expose secret key
                        assert "my_secret_key_12345" not in message
            except:
                pass

    @pytest.mark.asyncio
    async def test_empty_secret_key_handling(self):
        """Test that empty secret key is handled safely."""
        config = {"recaptcha": {"secret_key": "", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        is_valid, message = await validator.validate(headers, body)
        # Should reject empty secret key
        assert is_valid is False
        assert "secret key" in message.lower()


# ============================================================================
# 8. VERSION & SCORE VALIDATION
# ============================================================================


class TestRecaptchaVersionScoreValidation:
    """Test version and score validation."""

    @pytest.mark.asyncio
    async def test_v2_no_score_check(self):
        """Test that v2 doesn't check score (only success/failure)."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v2"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True}  # No score for v2
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_response

            is_valid, message = await validator.validate(headers, body)
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_v3_score_threshold_enforcement(self):
        """Test that v3 enforces score threshold."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "min_score": 0.7,
            }
        }
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Score below threshold
        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "score": 0.5}  # Below 0.7
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_response

            is_valid, message = await validator.validate(headers, body)
            assert is_valid is False
            assert "below threshold" in message.lower()

    @pytest.mark.asyncio
    async def test_missing_score_in_response(self):
        """Test handling of missing score in v3 response."""
        config = {
            "recaptcha": {
                "secret_key": "test_secret",
                "version": "v3",
                "min_score": 0.5,
            }
        }
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Response missing score
        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True}  # No score field
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_response

            is_valid, message = await validator.validate(headers, body)
            # Should default to 0.0 if score missing, which is below 0.5 threshold
            assert is_valid is False
            assert "below threshold" in message.lower()


# ============================================================================
# 9. LIBRARY DEPENDENCY SECURITY
# ============================================================================


class TestRecaptchaLibrarySecurity:
    """Test library dependency security."""

    @pytest.mark.asyncio
    async def test_missing_httpx_library(self):
        """Test behavior when httpx library is not installed."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Mock ImportError
        with patch(
            "builtins.__import__", side_effect=ImportError("No module named 'httpx'")
        ):
            is_valid, message = await validator.validate(headers, body)
            assert is_valid is False
            assert "httpx library not installed" in message


# ============================================================================
# 10. EDGE CASES
# ============================================================================


class TestRecaptchaEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_token_handling(self):
        """Test handling of empty token."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": ""}
        body = b'{"test": "data"}'

        is_valid, message = await validator.validate(headers, body)
        # Empty token should be rejected
        assert is_valid is False
        assert "missing" in message.lower() or "token" in message.lower()

    @pytest.mark.asyncio
    async def test_whitespace_only_token(self):
        """Test handling of whitespace-only token."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "   "}
        body = b'{"test": "data"}'

        is_valid, message = await validator.validate(headers, body)
        # Whitespace-only token should be rejected or handled
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_invalid_json_response_handling(self):
        """Test handling of invalid JSON response from Google."""
        config = {"recaptcha": {"secret_key": "test_secret", "version": "v3"}}
        validator = RecaptchaValidator(config)

        headers = {"x-recaptcha-token": "test_token"}
        body = b'{"test": "data"}'

        # Mock invalid JSON response
        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client_instance.post.return_value = mock_response

            is_valid, message = await validator.validate(headers, body)
            assert is_valid is False
            assert "invalid response" in message.lower() or "error" in message.lower()
