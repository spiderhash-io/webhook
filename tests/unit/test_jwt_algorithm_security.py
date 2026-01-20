"""
Security tests for JWT algorithm validation.
Tests that JWT algorithms are properly validated to prevent algorithm confusion attacks.
"""

import pytest
from src.validators import JWTValidator


class TestJWTAlgorithmSecurity:
    """Test suite for JWT algorithm validation security."""

    def test_none_algorithm_blocked(self):
        """Test that 'none' algorithm is explicitly blocked."""
        config = {"jwt": {"secret": "test_secret", "algorithm": "none"}}

        validator = JWTValidator(config)

        # Should raise ValueError during algorithm validation
        with pytest.raises(ValueError, match="explicitly blocked|not in the allowed"):
            validator._validate_algorithm("none")

    def test_weak_algorithms_blocked(self):
        """Test that weak algorithms are blocked."""
        weak_algorithms = ["HS1", "MD5", "none"]

        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        for weak_alg in weak_algorithms:
            with pytest.raises(ValueError, match="blocked|not in the allowed"):
                validator._validate_algorithm(weak_alg)

    def test_strong_algorithms_allowed(self):
        """Test that strong algorithms are allowed."""
        strong_algorithms = [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
        ]

        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        for alg in strong_algorithms:
            # Should not raise an exception
            validated = validator._validate_algorithm(alg)
            assert validated == alg.upper()

    def test_case_insensitive_algorithm_validation(self):
        """Test that algorithm validation is case-insensitive."""
        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        # Lowercase should be normalized to uppercase
        validated = validator._validate_algorithm("hs256")
        assert validated == "HS256"

        # Mixed case should be normalized
        validated = validator._validate_algorithm("Hs256")
        assert validated == "HS256"

        # Uppercase should work
        validated = validator._validate_algorithm("HS256")
        assert validated == "HS256"

    def test_unknown_algorithm_rejected(self):
        """Test that unknown algorithms are rejected."""
        unknown_algorithms = [
            "CUSTOM256",
            "UNKNOWN",
            "WEAK",
            "TEST",
        ]

        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        for unknown_alg in unknown_algorithms:
            with pytest.raises(ValueError, match="not in the allowed"):
                validator._validate_algorithm(unknown_alg)

    def test_empty_algorithm_rejected(self):
        """Test that empty algorithm is rejected."""
        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        with pytest.raises(ValueError, match="cannot be empty|non-empty string"):
            validator._validate_algorithm("")

        with pytest.raises(ValueError, match="cannot be empty|non-empty string"):
            validator._validate_algorithm("   ")

    def test_none_type_rejected(self):
        """Test that None algorithm is rejected."""
        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        with pytest.raises(ValueError, match="non-empty string"):
            validator._validate_algorithm(None)

    def test_algorithm_whitelist_enforced(self):
        """Test that only whitelisted algorithms are allowed."""
        # Test that all allowed algorithms are in the whitelist
        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        # All algorithms in ALLOWED_ALGORITHMS should validate
        for alg in validator.ALLOWED_ALGORITHMS:
            validated = validator._validate_algorithm(alg)
            assert validated == alg

        # Algorithms not in whitelist should be rejected
        test_alg = "NOT_IN_WHITELIST"
        assert test_alg not in validator.ALLOWED_ALGORITHMS
        with pytest.raises(ValueError, match="not in the allowed"):
            validator._validate_algorithm(test_alg)

    def test_blocked_algorithms_list_enforced(self):
        """Test that blocked algorithms are explicitly rejected."""
        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        # All algorithms in BLOCKED_ALGORITHMS should be rejected
        for alg in validator.BLOCKED_ALGORITHMS:
            with pytest.raises(
                ValueError, match="explicitly blocked|not in the allowed"
            ):
                validator._validate_algorithm(alg)

    @pytest.mark.asyncio
    async def test_algorithm_in_config_validated(self):
        """Test that algorithm from config is validated during JWT validation."""
        # Test with blocked algorithm
        config = {"jwt": {"secret": "test_secret", "algorithm": "none"}}

        validator = JWTValidator(config)
        headers = {"authorization": "Bearer test_token"}

        # Should fail at algorithm validation
        result = await validator.validate(headers, b"{}")
        assert not result[0]
        assert (
            "algorithm validation failed" in result[1].lower()
            or "blocked" in result[1].lower()
        )

    def test_default_algorithm_validated(self):
        """Test that default algorithm (HS256) is validated and allowed."""
        config = {
            "jwt": {
                "secret": "test_secret",
                # algorithm defaults to 'HS256'
            }
        }

        validator = JWTValidator(config)

        # Default algorithm should be validated and allowed
        # This test just ensures the validation path works for default
        # Actual JWT validation will fail without a valid token, but algorithm should pass
        validated = validator._validate_algorithm("HS256")
        assert validated == "HS256"

    def test_algorithm_normalization(self):
        """Test that algorithm names are normalized to uppercase."""
        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        # Test various case combinations
        test_cases = [
            ("hs256", "HS256"),
            ("Hs256", "HS256"),
            ("HS256", "HS256"),
            ("rs512", "RS512"),
            ("ES384", "ES384"),
        ]

        for input_alg, expected_alg in test_cases:
            validated = validator._validate_algorithm(input_alg)
            assert validated == expected_alg

    def test_multiple_strong_algorithms_allowed(self):
        """Test that multiple strong algorithms can be validated."""
        strong_algorithms = ["HS256", "RS256", "ES256", "PS256"]

        config = {
            "jwt": {
                "secret": "test_secret",
            }
        }

        validator = JWTValidator(config)

        for alg in strong_algorithms:
            validated = validator._validate_algorithm(alg)
            assert validated == alg

    @pytest.mark.asyncio
    async def test_algorithm_validation_before_jwt_decode(self):
        """Test that algorithm validation happens before JWT decode."""
        config = {
            "jwt": {"secret": "test_secret", "algorithm": "none"}  # Blocked algorithm
        }

        validator = JWTValidator(config)
        headers = {"authorization": "Bearer invalid_token"}

        # Should fail at algorithm validation, not at JWT decode
        result = await validator.validate(headers, b"{}")
        assert not result[0]
        # Error should mention algorithm validation, not JWT decode errors
        assert "algorithm" in result[1].lower()
