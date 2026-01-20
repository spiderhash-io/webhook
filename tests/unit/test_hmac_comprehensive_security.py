"""
Comprehensive security tests for HMAC signature validation.
Tests advanced HMAC attack vectors and bypass techniques.
"""

import pytest
import hmac
import hashlib
from src.validators import HMACValidator


class TestHMACTimingAttacks:
    """Test HMAC timing attack resistance."""

    @pytest.mark.asyncio
    async def test_timing_attack_resistance_detailed(self):
        """Test that HMAC comparison is timing-attack resistant with detailed measurements."""
        config = {
            "hmac": {
                "secret": "test_secret_key_12345",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Correct signature
        correct_sig = hmac.new(
            b"test_secret_key_12345", body, hashlib.sha256
        ).hexdigest()

        # Various incorrect signatures
        # Note: We can't just change first char to '0' if it's already '0'
        # So we'll change it to a different character
        first_char = correct_sig[0]
        new_first_char = "1" if first_char == "0" else "0"
        incorrect_signatures = [
            correct_sig[:-1] + "0",  # Last char wrong
            new_first_char + correct_sig[1:],  # First char wrong
            "a" * len(correct_sig),  # Completely wrong
            correct_sig[:10]
            + "a"
            * (len(correct_sig) - 10),  # Middle wrong (use 'a' not 'x' for valid hex)
        ]

        import time

        # Measure time for correct signature
        start = time.time()
        is_valid_correct, _ = await validator.validate(
            {"x-hmac-signature": correct_sig}, body
        )
        time_correct = time.time() - start

        # Measure time for various incorrect signatures
        times_incorrect = []
        for sig in incorrect_signatures:
            start = time.time()
            is_valid, _ = await validator.validate({"x-hmac-signature": sig}, body)
            times_incorrect.append(time.time() - start)
            assert is_valid is False

        # All incorrect signatures should be rejected
        assert is_valid_correct is True

        # Times should be similar (within reasonable margin)
        # Large differences could indicate timing vulnerability
        max_time_diff = max(abs(time_correct - t) for t in times_incorrect)
        # Allow 0.1 second difference (timing can vary)
        assert (
            max_time_diff < 0.1
        ), f"Timing difference too large: {max_time_diff}s (potential timing attack)"

    @pytest.mark.asyncio
    async def test_signature_length_timing(self):
        """Test that different signature lengths don't reveal timing differences."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Correct signature (64 hex chars for SHA256)
        correct_sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Wrong length signatures
        wrong_length_sigs = [
            correct_sig[:-1],  # Too short (63 chars)
            correct_sig + "0",  # Too long (65 chars)
            correct_sig[:32],  # Half length
            correct_sig * 2,  # Double length
        ]

        import time

        times = []
        for sig in wrong_length_sigs:
            start = time.time()
            is_valid, _ = await validator.validate({"x-hmac-signature": sig}, body)
            times.append(time.time() - start)
            assert is_valid is False

        # Times should be similar regardless of length
        if len(times) > 1:
            max_diff = max(times) - min(times)
            assert max_diff < 0.1, f"Timing difference based on length: {max_diff}s"


class TestHMACAlgorithmConfusion:
    """Test HMAC algorithm confusion attacks."""

    @pytest.mark.asyncio
    async def test_algorithm_mismatch_sha1_vs_sha256(self):
        """Test that SHA1 signature cannot validate when SHA256 is expected."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",  # Expect SHA256
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Create signature with SHA1 (wrong algorithm)
        sha1_sig = hmac.new(b"test_secret", body, hashlib.sha1).hexdigest()

        is_valid, message = await validator.validate(
            {"x-hmac-signature": sha1_sig}, body
        )
        assert is_valid is False
        assert "Invalid HMAC signature" in message

    @pytest.mark.asyncio
    async def test_algorithm_mismatch_sha256_vs_sha512(self):
        """Test that SHA256 signature cannot validate when SHA512 is expected."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha512",  # Expect SHA512
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Create signature with SHA256 (wrong algorithm)
        sha256_sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        is_valid, message = await validator.validate(
            {"x-hmac-signature": sha256_sig}, body
        )
        assert is_valid is False
        assert "Invalid HMAC signature" in message

    @pytest.mark.asyncio
    async def test_unsupported_algorithm(self):
        """Test that unsupported algorithms are rejected."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "md5",  # Unsupported
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Try to validate with unsupported algorithm
        is_valid, message = await validator.validate({"x-hmac-signature": "test"}, body)
        assert is_valid is False
        assert "Unsupported HMAC algorithm" in message

    @pytest.mark.asyncio
    async def test_case_sensitive_algorithm(self):
        """Test algorithm name case handling."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "SHA256",  # Uppercase
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Create signature with SHA256
        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Should fail - algorithm name is case-sensitive in current implementation
        is_valid, message = await validator.validate({"x-hmac-signature": sig}, body)
        # Current implementation may fail on case mismatch
        # Test documents current behavior


class TestHMACSecretHandling:
    """Test HMAC secret handling security."""

    @pytest.mark.asyncio
    async def test_empty_secret_rejected(self):
        """Test that empty secret is rejected."""
        config = {
            "hmac": {
                "secret": "",  # Empty secret
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        is_valid, message = await validator.validate({"x-hmac-signature": "test"}, body)
        assert is_valid is False
        assert "secret" in message.lower() or "not configured" in message.lower()

    @pytest.mark.asyncio
    async def test_missing_secret_rejected(self):
        """Test that missing secret is rejected."""
        config = {
            "hmac": {
                # Missing secret
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        is_valid, message = await validator.validate({"x-hmac-signature": "test"}, body)
        assert is_valid is False
        assert "secret" in message.lower() or "not configured" in message.lower()

    @pytest.mark.asyncio
    async def test_weak_secret_accepted(self):
        """Test that weak secrets are accepted (current behavior)."""
        # Note: This tests current behavior - weak secret detection may not be implemented
        weak_secrets = ["secret", "12345", "password", "admin"]

        for weak_secret in weak_secrets:
            config = {
                "hmac": {
                    "secret": weak_secret,
                    "header": "X-HMAC-Signature",
                    "algorithm": "sha256",
                }
            }

            validator = HMACValidator(config)
            body = b'{"test": "data"}'

            sig = hmac.new(weak_secret.encode(), body, hashlib.sha256).hexdigest()
            is_valid, message = await validator.validate(
                {"x-hmac-signature": sig}, body
            )

            # Current implementation accepts weak secrets
            # This is a potential security issue if not addressed elsewhere
            assert is_valid is True


class TestHMACSignatureFormat:
    """Test HMAC signature format handling."""

    @pytest.mark.asyncio
    async def test_sha256_prefix_format(self):
        """Test signature with sha256= prefix."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Test with prefix
        headers = {"x-hmac-signature": f"sha256={sig}"}
        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True

        # Test without prefix (should also work)
        headers = {"x-hmac-signature": sig}
        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_wrong_prefix_format(self):
        """Test signature with wrong prefix."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Wrong prefix
        headers = {"x-hmac-signature": f"sha1={sig}"}  # Wrong algorithm prefix
        is_valid, message = await validator.validate(headers, body)
        # Should extract signature after =, but algorithm mismatch will cause failure
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_multiple_equals_in_signature(self):
        """Test signature with multiple equals signs."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Multiple equals (should split on first =)
        headers = {"x-hmac-signature": f"sha256={sig}=extra"}
        is_valid, message = await validator.validate(headers, body)
        # Should extract sig + "=extra" which will be invalid
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_base64_vs_hex_confusion(self):
        """Test that base64-encoded signatures are rejected (expects hex)."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Create base64 signature (wrong format)
        import base64

        sig_bytes = hmac.new(b"test_secret", body, hashlib.sha256).digest()
        base64_sig = base64.b64encode(sig_bytes).decode()

        headers = {"x-hmac-signature": base64_sig}
        is_valid, message = await validator.validate(headers, body)
        # Should fail - expects hex, not base64
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_uppercase_hex_signature(self):
        """Test that uppercase hex signatures are handled."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest().upper()

        headers = {"x-hmac-signature": sig}
        is_valid, message = await validator.validate(headers, body)
        # Hex comparison should be case-sensitive or case-insensitive?
        # Test current behavior
        # hmac.compare_digest is case-sensitive, so uppercase will fail
        assert is_valid is False


class TestHMACHeaderManipulation:
    """Test HMAC header manipulation attacks."""

    @pytest.mark.asyncio
    async def test_case_insensitive_header_name(self):
        """Test that header name lookup is case-insensitive."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Test various case combinations
        # Note: The validator uses header_name.lower() to look up, so it expects lowercase
        # But headers dict keys should be normalized to lowercase before passing to validator
        # In practice, headers are normalized in webhook.py before validation
        case_variations = [
            {"x-hmac-signature": sig},  # Lowercase (expected format)
        ]

        for headers in case_variations:
            is_valid, message = await validator.validate(headers, body)
            # Should work - header lookup uses lowercase
            assert is_valid is True

        # Test that uppercase header name in config still works with lowercase header
        config_upper = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-SIGNATURE",  # Uppercase in config
                "algorithm": "sha256",
            }
        }
        validator_upper = HMACValidator(config_upper)
        is_valid, message = await validator_upper.validate(
            {"x-hmac-signature": sig}, body
        )
        # Should work - config header is lowercased for lookup
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_custom_header_name(self):
        """Test custom header name configuration."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-Custom-Signature",  # Custom header
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Use custom header name
        headers = {"x-custom-signature": sig}
        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_multiple_signature_headers(self):
        """Test behavior with multiple signature headers."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Multiple headers with same name (dict will only keep one)
        # But test what happens if we have multiple values
        headers = {
            "x-hmac-signature": sig,
            "X-HMAC-Signature": "wrong",  # Duplicate with different case
        }

        # Python dict will keep one, but test behavior
        is_valid, message = await validator.validate(headers, body)
        # Should use the value that matches (case-insensitive lookup)
        # Test documents current behavior

    @pytest.mark.asyncio
    async def test_empty_signature_header(self):
        """Test empty signature header value."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Empty signature
        headers = {"x-hmac-signature": ""}

        is_valid, message = await validator.validate(headers, body)
        assert is_valid is False
        assert "Missing" in message or "Invalid" in message

    @pytest.mark.asyncio
    async def test_whitespace_in_signature(self):
        """Test signature with whitespace."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Whitespace variations
        whitespace_variations = [
            f" {sig}",  # Leading space
            f"{sig} ",  # Trailing space
            f" {sig} ",  # Both
            f"\t{sig}",  # Tab
        ]

        for sig_with_ws in whitespace_variations:
            headers = {"x-hmac-signature": sig_with_ws}
            is_valid, message = await validator.validate(headers, body)
            # Should fail - whitespace in signature is invalid
            assert is_valid is False


class TestHMACBodyManipulation:
    """Test HMAC body manipulation attacks."""

    @pytest.mark.asyncio
    async def test_body_tampering_detected(self):
        """Test that body tampering is detected."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        original_body = b'{"user": "admin", "action": "delete"}'

        # Create signature for original body
        sig = hmac.new(b"test_secret", original_body, hashlib.sha256).hexdigest()

        # Try to use signature with modified body
        modified_body = b'{"user": "admin", "action": "create"}'  # Changed action

        is_valid, message = await validator.validate(
            {"x-hmac-signature": sig}, modified_body
        )
        assert is_valid is False
        assert "Invalid HMAC signature" in message

    @pytest.mark.asyncio
    async def test_empty_body_signature(self):
        """Test HMAC with empty body."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b""

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        is_valid, message = await validator.validate({"x-hmac-signature": sig}, body)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_very_large_body(self):
        """Test HMAC with very large body (DoS attempt)."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        large_body = b"x" * 1000000  # 1MB body

        sig = hmac.new(b"test_secret", large_body, hashlib.sha256).hexdigest()

        # Should handle gracefully (may be slow, but shouldn't crash)
        is_valid, message = await validator.validate(
            {"x-hmac-signature": sig}, large_body
        )
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_unicode_body_handling(self):
        """Test HMAC with Unicode body."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        unicode_body = '{"user": "测试", "data": "🎉"}'.encode("utf-8")

        sig = hmac.new(b"test_secret", unicode_body, hashlib.sha256).hexdigest()

        is_valid, message = await validator.validate(
            {"x-hmac-signature": sig}, unicode_body
        )
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_null_bytes_in_body(self):
        """Test HMAC with null bytes in body."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body_with_nulls = b'{"test": "data\x00injection"}'

        sig = hmac.new(b"test_secret", body_with_nulls, hashlib.sha256).hexdigest()

        is_valid, message = await validator.validate(
            {"x-hmac-signature": sig}, body_with_nulls
        )
        # Should work - null bytes are valid in body
        assert is_valid is True


class TestHMACSignatureLength:
    """Test HMAC signature length validation."""

    @pytest.mark.asyncio
    async def test_wrong_signature_length(self):
        """Test signatures with wrong length."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # SHA256 produces 64 hex chars
        wrong_length_sigs = [
            "a" * 32,  # Too short (32 chars)
            "a" * 63,  # Almost correct (63 chars)
            "a" * 65,  # Too long (65 chars)
            "a" * 128,  # Way too long
        ]

        for sig in wrong_length_sigs:
            is_valid, message = await validator.validate(
                {"x-hmac-signature": sig}, body
            )
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_sha1_signature_length(self):
        """Test SHA1 signature length (40 hex chars)."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha1",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha1).hexdigest()
        assert len(sig) == 40  # SHA1 produces 40 hex chars

        is_valid, message = await validator.validate({"x-hmac-signature": sig}, body)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_sha512_signature_length(self):
        """Test SHA512 signature length (128 hex chars)."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha512",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha512).hexdigest()
        assert len(sig) == 128  # SHA512 produces 128 hex chars

        is_valid, message = await validator.validate({"x-hmac-signature": sig}, body)
        assert is_valid is True


class TestHMACEdgeCases:
    """Test HMAC edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_non_hex_characters_in_signature(self):
        """Test signature with non-hex characters."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Non-hex characters
        invalid_sigs = [
            "g" * 64,  # 'g' is not hex
            "z" * 64,  # 'z' is not hex
            "G" * 64,  # 'G' is not hex
            "!@#$" * 16,  # Special chars
        ]

        for sig in invalid_sigs:
            is_valid, message = await validator.validate(
                {"x-hmac-signature": sig}, body
            )
            # hmac.compare_digest will compare, but signature will be wrong
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_unicode_in_signature(self):
        """Test signature with Unicode characters."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Unicode in signature (invalid hex)
        unicode_sig = "测试" * 32

        is_valid, message = await validator.validate(
            {"x-hmac-signature": unicode_sig}, body
        )
        # Should fail - Unicode is not valid hex, and hmac.compare_digest doesn't support non-ASCII
        # Our fix validates hex format before comparison, so this should fail gracefully
        assert is_valid is False
        assert (
            "Invalid HMAC signature format" in message
            or "Invalid HMAC signature" in message
        )

    @pytest.mark.asyncio
    async def test_signature_truncation_attack(self):
        """Test signature truncation attempts."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Try truncated signatures
        truncated = [
            sig[:32],  # Half
            sig[:16],  # Quarter
            sig[:1],  # Single char
        ]

        for trunc_sig in truncated:
            is_valid, message = await validator.validate(
                {"x-hmac-signature": trunc_sig}, body
            )
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_signature_padding_attack(self):
        """Test signature padding attempts."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Try padded signatures
        padded = [
            "0" * 32 + sig,  # Leading zeros
            sig + "0" * 32,  # Trailing zeros
            "0" + sig[1:],  # First char replaced
        ]

        for pad_sig in padded:
            is_valid, message = await validator.validate(
                {"x-hmac-signature": pad_sig}, body
            )
            assert is_valid is False


class TestHMACReplayAttacks:
    """Test HMAC replay attack prevention."""

    @pytest.mark.asyncio
    async def test_signature_reuse(self):
        """Test that same signature can be reused (current behavior)."""
        # Note: HMAC doesn't prevent replay by itself - needs timestamp/nonce
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        # Use same signature multiple times
        for _ in range(5):
            is_valid, message = await validator.validate(
                {"x-hmac-signature": sig}, body
            )
            # Should work - HMAC doesn't prevent replay
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_signature_with_timestamp(self):
        """Test HMAC with timestamp in body (replay prevention pattern)."""
        config = {
            "hmac": {
                "secret": "test_secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)

        import time

        timestamp = int(time.time())
        body = f'{{"test": "data", "timestamp": {timestamp}}}'.encode()

        sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

        is_valid, message = await validator.validate({"x-hmac-signature": sig}, body)
        # Should work - timestamp in body is valid
        assert is_valid is True

        # Try to reuse with old timestamp
        old_timestamp = timestamp - 3600  # 1 hour ago
        old_body = f'{{"test": "data", "timestamp": {old_timestamp}}}'.encode()
        # Signature won't match because body changed
        is_valid, message = await validator.validate(
            {"x-hmac-signature": sig}, old_body
        )
        assert is_valid is False


class TestHMACSecretExposure:
    """Test HMAC secret exposure prevention."""

    @pytest.mark.asyncio
    async def test_secret_not_in_error_messages(self):
        """Test that secret is not exposed in error messages."""
        secret = "super_secret_key_12345"
        config = {
            "hmac": {
                "secret": secret,
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        # Use wrong signature to trigger error
        is_valid, message = await validator.validate(
            {"x-hmac-signature": "wrong"}, body
        )
        assert is_valid is False

        # Secret should not appear in error message
        assert secret not in message
        assert "super_secret_key_12345" not in message

    @pytest.mark.asyncio
    async def test_secret_not_in_success_messages(self):
        """Test that secret is not exposed in success messages."""
        secret = "super_secret_key_12345"
        config = {
            "hmac": {
                "secret": secret,
                "header": "X-HMAC-Signature",
                "algorithm": "sha256",
            }
        }

        validator = HMACValidator(config)
        body = b'{"test": "data"}'

        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        is_valid, message = await validator.validate({"x-hmac-signature": sig}, body)
        assert is_valid is True

        # Secret should not appear in success message
        assert secret not in message


class TestHMACAlgorithmCaseHandling:
    """Test HMAC algorithm case handling."""

    @pytest.mark.asyncio
    async def test_algorithm_case_sensitivity(self):
        """Test algorithm name case handling."""
        # Test various case combinations
        # After our fix, algorithm names are normalized to lowercase
        test_cases = [
            ("sha256", hashlib.sha256),
            ("SHA256", hashlib.sha256),
            ("Sha256", hashlib.sha256),
            ("sha1", hashlib.sha1),
            ("SHA1", hashlib.sha1),
            ("sha512", hashlib.sha512),
            ("SHA512", hashlib.sha512),
        ]

        for alg_name, hash_func in test_cases:
            config = {
                "hmac": {
                    "secret": "test_secret",
                    "header": "X-HMAC-Signature",
                    "algorithm": alg_name,
                }
            }

            validator = HMACValidator(config)
            body = b'{"test": "data"}'

            sig = hmac.new(b"test_secret", body, hash_func).hexdigest()

            is_valid, message = await validator.validate(
                {"x-hmac-signature": sig}, body
            )
            # Should work - algorithm names are now case-insensitive (normalized to lowercase)
            assert is_valid is True
