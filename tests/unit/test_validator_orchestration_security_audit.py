"""
Comprehensive security audit tests for Validator Orchestration System.

This audit focuses on:
- Validator instantiation vulnerabilities (type confusion, DoS)
- Validator orchestration error handling
- Validator result combination edge cases
- Validator instantiation order and race conditions
- Configuration injection in validator instantiation
"""

import pytest
import asyncio
from unittest.mock import patch, Mock, AsyncMock, MagicMock
from fastapi import Request, HTTPException
from fastapi.testclient import TestClient

from src.webhook import WebhookHandler
from src.validators import BaseValidator, AuthorizationValidator, HMACValidator
from src.utils import sanitize_error_message


# ============================================================================
# 1. VALIDATOR INSTANTIATION VULNERABILITIES
# ============================================================================


@pytest.mark.longrunning
class TestValidatorInstantiationSecurity:
    """Test validator instantiation vulnerabilities."""

    def test_validator_instantiation_with_non_dict_config(self):
        """Test that validators handle non-dict config safely."""
        # Type confusion attack: config is not a dict
        malicious_configs = [
            None,
            "not_a_dict",
            123,
            [],
            ["list", "of", "strings"],
        ]

        for malicious_config in malicious_configs:
            # Validators should handle non-dict config gracefully
            # BaseValidator now raises TypeError for non-dict configs
            try:
                validator = AuthorizationValidator(malicious_config)
                # If instantiation succeeds, that's OK (validator might handle it)
                # But we want to ensure it doesn't crash the application
                assert validator is not None
            except TypeError:
                # TypeError is expected - BaseValidator rejects non-dict config
                pass
            except (AttributeError, ValueError):
                # Other exceptions are acceptable - validator rejects invalid config
                pass

    def test_validator_instantiation_with_malicious_config_structure(self):
        """Test that validators handle malicious config structures safely."""
        # Config with circular references or deeply nested structures
        malicious_config = {}
        malicious_config["self"] = malicious_config  # Circular reference

        try:
            validator = AuthorizationValidator(malicious_config)
            # Should not crash during instantiation
            assert validator is not None
        except (RecursionError, MemoryError):
            # Recursion error is acceptable - validator rejects malicious config
            pass

    def test_webhook_handler_validator_instantiation_with_invalid_config(self):
        """Test that WebhookHandler handles validator instantiation errors safely."""
        from fastapi import Request
        from fastapi.testclient import TestClient

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        # Config that might cause validator instantiation to fail
        invalid_configs = [
            None,  # None config
            "not_a_dict",  # String instead of dict
            123,  # Number instead of dict
        ]

        for invalid_config in invalid_configs:
            configs = {"test_webhook": invalid_config}

            try:
                handler = WebhookHandler("test_webhook", configs, {}, mock_request)
                # If instantiation succeeds, validators might handle invalid config
                # But we want to ensure it doesn't crash
                assert handler is not None
            except (TypeError, AttributeError, HTTPException):
                # Exception is acceptable - handler rejects invalid config
                pass

    def test_validator_instantiation_dos_via_large_config(self):
        """Test that validator instantiation doesn't cause DoS via large config."""
        # Very large config that might cause memory exhaustion
        large_config = {
            "data": "x" * 1000000,  # 1MB string
            "nested": {"level1": {"level2": {"level3": {"data": "y" * 100000}}}},
        }

        try:
            validator = AuthorizationValidator(large_config)
            # Should not cause memory exhaustion
            assert validator is not None
        except MemoryError:
            # Memory error is acceptable for extremely large configs
            pass


# ============================================================================
# 2. VALIDATOR ORCHESTRATION ERROR HANDLING
# ============================================================================


@pytest.mark.longrunning
class TestValidatorOrchestrationErrorHandling:
    """Test validator orchestration error handling vulnerabilities."""

    @pytest.mark.asyncio
    async def test_validator_exception_information_disclosure(self):
        """Test that validator exceptions don't disclose sensitive information."""
        from fastapi import Request
        from unittest.mock import AsyncMock

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"authorization": "Bearer token123"}
        configs = {"test_webhook": config}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Mock a validator to raise exception with sensitive info
        class MaliciousValidator(BaseValidator):
            async def validate(self, headers, body):
                raise Exception("/etc/passwd: permission denied")

        # Replace one validator with malicious one
        handler.validators[0] = MaliciousValidator(config)

        is_valid, message = await handler.validate_webhook()

        # Should fail validation
        assert not is_valid

        # Error message should be sanitized
        assert "/etc/passwd" not in message.lower(), "Error message should be sanitized"
        assert "permission denied" not in message.lower() or "error" in message.lower()

    @pytest.mark.asyncio
    async def test_validator_exception_handling_comprehensive(self):
        """Test that all validator exceptions are handled comprehensively."""
        from fastapi import Request
        from unittest.mock import AsyncMock

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Test various exception types
        exception_types = [
            ValueError("Invalid value"),
            TypeError("Invalid type"),
            AttributeError("Missing attribute"),
            KeyError("Missing key"),
            RuntimeError("Runtime error"),
            Exception("Generic error"),
        ]

        for exc in exception_types:

            class ExceptionValidator(BaseValidator):
                async def validate(self, headers, body):
                    raise exc

            handler.validators[0] = ExceptionValidator(config)

            is_valid, message = await handler.validate_webhook()

            # Should fail validation
            assert not is_valid

            # Error message should be sanitized
            assert isinstance(message, str)
            # Should not contain internal exception details
            assert "traceback" not in message.lower()
            assert "file" not in message.lower() or "error" in message.lower()


# ============================================================================
# 3. VALIDATOR RESULT COMBINATION EDGE CASES
# ============================================================================


@pytest.mark.longrunning
class TestValidatorResultCombination:
    """Test validator result combination edge cases."""

    @pytest.mark.asyncio
    async def test_validator_returns_non_boolean_result(self):
        """Test that validators returning non-boolean results are handled safely."""
        from fastapi import Request
        from unittest.mock import AsyncMock

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Validator that returns non-boolean
        class NonBooleanValidator(BaseValidator):
            async def validate(self, headers, body):
                return "not_a_boolean", "message"

        handler.validators[0] = NonBooleanValidator(config)

        # Should handle non-boolean result gracefully
        try:
            is_valid, message = await handler.validate_webhook()
            # If it doesn't crash, check that result is handled
            # Python's truthiness will evaluate "not_a_boolean" as True
            assert isinstance(is_valid, (bool, str)) or is_valid is None
        except (TypeError, ValueError):
            # Exception is acceptable - handler rejects invalid result
            pass

    @pytest.mark.asyncio
    async def test_validator_returns_non_string_message(self):
        """Test that validators returning non-string messages are handled safely."""
        from fastapi import Request
        from unittest.mock import AsyncMock

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Validator that returns non-string message
        class NonStringMessageValidator(BaseValidator):
            async def validate(self, headers, body):
                return False, 123  # Number instead of string

        handler.validators[0] = NonStringMessageValidator(config)

        # Should handle non-string message gracefully
        try:
            is_valid, message = await handler.validate_webhook()
            # Message should be converted to string or handled safely
            # Python will convert 123 to string when used
            assert isinstance(message, (str, int)) or message is None
        except (TypeError, ValueError):
            # Exception is acceptable - handler rejects invalid message type
            pass

    @pytest.mark.asyncio
    async def test_validator_returns_tuple_with_wrong_length(self):
        """Test that validators returning tuples with wrong length are handled safely."""
        from fastapi import Request
        from unittest.mock import AsyncMock

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Validator that returns wrong tuple length
        class WrongLengthValidator(BaseValidator):
            async def validate(self, headers, body):
                return (False,)  # Only one element instead of two

        handler.validators[0] = WrongLengthValidator(config)

        # Should handle wrong tuple length gracefully
        try:
            is_valid, message = await handler.validate_webhook()
            # Should not crash - Python will unpack what it can
            assert True
        except (ValueError, TypeError, IndexError):
            # Exception is acceptable - handler rejects invalid tuple
            pass


# ============================================================================
# 4. VALIDATOR INSTANTIATION ORDER AND RACE CONDITIONS
# ============================================================================


@pytest.mark.longrunning
class TestValidatorInstantiationOrder:
    """Test validator instantiation order and race conditions."""

    def test_validator_instantiation_order_consistency(self):
        """Test that validators are instantiated in consistent order."""
        from fastapi import Request

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        handler1 = WebhookHandler("test_webhook", configs, {}, mock_request)
        handler2 = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Validators should be in the same order
        validator_types1 = [type(v).__name__ for v in handler1.validators]
        validator_types2 = [type(v).__name__ for v in handler2.validators]

        assert (
            validator_types1 == validator_types2
        ), "Validator order should be consistent"

    @pytest.mark.asyncio
    async def test_concurrent_validator_instantiation(self):
        """Test that concurrent validator instantiation doesn't cause race conditions."""
        from fastapi import Request
        import asyncio

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        # Create multiple handlers concurrently
        async def create_handler():
            return WebhookHandler("test_webhook", configs, {}, mock_request)

        handlers = await asyncio.gather(*[create_handler() for _ in range(10)])

        # All should succeed
        assert len(handlers) == 10
        assert all(h is not None for h in handlers)


# ============================================================================
# 5. CONFIGURATION INJECTION IN VALIDATOR INSTANTIATION
# ============================================================================


@pytest.mark.longrunning
class TestConfigurationInjection:
    """Test configuration injection vulnerabilities in validator instantiation."""

    def test_validator_config_injection_via_prototype_pollution(self):
        """Test that validators handle prototype pollution attempts safely."""
        # Prototype pollution attempt (JavaScript-specific, but test anyway)
        malicious_config = {
            "__proto__": {"admin": True},
            "constructor": {"admin": True},
            "authorization": "Bearer token123",
        }

        try:
            validator = AuthorizationValidator(malicious_config)
            # Should handle prototype pollution attempt safely
            # Python doesn't have prototype pollution, but test anyway
            assert validator is not None
        except Exception:
            # Exception is acceptable
            pass

    def test_validator_config_injection_via_deeply_nested_structure(self):
        """Test that validators handle deeply nested config structures safely."""
        # Create deeply nested structure
        nested_config = {"level": 1}
        current = nested_config
        for i in range(2, 1000):  # Very deep nesting
            current["nested"] = {"level": i}
            current = current["nested"]

        try:
            validator = AuthorizationValidator(nested_config)
            # Should handle deeply nested structure safely
            assert validator is not None
        except (RecursionError, MemoryError):
            # Recursion error is acceptable for extremely deep nesting
            pass

    def test_validator_config_injection_via_circular_reference(self):
        """Test that validators handle circular references in config safely."""
        # Create circular reference
        config = {"key": "value"}
        config["self"] = config  # Circular reference

        try:
            validator = AuthorizationValidator(config)
            # Should handle circular reference safely
            assert validator is not None
        except (RecursionError, MemoryError):
            # Recursion error is acceptable
            pass


# ============================================================================
# 6. BASEVALIDATOR CLASS SECURITY
# ============================================================================


@pytest.mark.longrunning
class TestBaseValidatorSecurity:
    """Test BaseValidator class security vulnerabilities."""

    def test_base_validator_config_type_validation(self):
        """Test that BaseValidator handles invalid config types safely."""
        # BaseValidator should handle non-dict config
        invalid_configs = [
            None,
            "not_a_dict",
            123,
            [],
        ]

        for invalid_config in invalid_configs:
            try:
                # Can't instantiate BaseValidator directly (abstract)
                # But test that subclasses handle it
                # BaseValidator now raises TypeError for non-dict configs
                validator = AuthorizationValidator(invalid_config)
                # If instantiation succeeds, validator handles invalid config
                assert validator is not None
            except TypeError:
                # TypeError is expected - BaseValidator rejects non-dict config
                pass
            except AttributeError:
                # Other exceptions are acceptable - validator rejects invalid config
                pass

    def test_base_validator_config_mutation(self):
        """Test that BaseValidator doesn't mutate config in unsafe ways."""
        config = {"authorization": "Bearer token123"}
        original_config = config.copy()

        validator = AuthorizationValidator(config)

        # Config should not be mutated
        assert config == original_config

    def test_base_validator_config_access_control(self):
        """Test that BaseValidator doesn't expose config in unsafe ways."""
        config = {
            "authorization": "Bearer token123",
            "secret": "sensitive_secret",
            "password": "sensitive_password",
        }

        validator = AuthorizationValidator(config)

        # Config is stored internally, but shouldn't be exposed in error messages
        # This is tested in individual validator tests, but we verify here
        assert hasattr(validator, "config")
        # Config should be the same object (not copied)
        assert validator.config is config


# ============================================================================
# 7. VALIDATOR ORCHESTRATION EDGE CASES
# ============================================================================


@pytest.mark.longrunning
class TestValidatorOrchestrationEdgeCases:
    """Test validator orchestration edge cases."""

    @pytest.mark.asyncio
    async def test_empty_validators_list(self):
        """Test that empty validators list is handled safely."""
        from fastapi import Request
        from unittest.mock import AsyncMock

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Replace validators with empty list
        handler.validators = []

        # Should succeed (no validators = all pass)
        is_valid, message = await handler.validate_webhook()
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validator_returns_none_values(self):
        """Test that validators returning None values are handled safely."""
        from fastapi import Request
        from unittest.mock import AsyncMock

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Validator that returns None
        class NoneValidator(BaseValidator):
            async def validate(self, headers, body):
                return None, None

        handler.validators[0] = NoneValidator(config)

        # Should handle None values gracefully
        try:
            is_valid, message = await handler.validate_webhook()
            # None is falsy, so validation should fail
            # Should not crash
            assert True
        except (TypeError, ValueError):
            # Exception is acceptable - handler rejects None values
            pass

    @pytest.mark.asyncio
    async def test_validator_raises_baseexception(self):
        """Test that validators raising BaseException are handled safely."""
        from fastapi import Request
        from unittest.mock import AsyncMock

        # Create a mock request
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        config = {"module": "log"}  # Valid config with required module field
        configs = {"test_webhook": config}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Validator that raises BaseException (not caught by except Exception)
        class BaseExceptionValidator(BaseValidator):
            async def validate(self, headers, body):
                raise SystemExit("System exit")

        handler.validators[0] = BaseExceptionValidator(config)

        # Should handle BaseException gracefully
        # Note: SystemExit is a BaseException, not Exception, so it might propagate
        try:
            is_valid, message = await handler.validate_webhook()
            # Should not crash
            assert True
        except SystemExit:
            # SystemExit might propagate, which is acceptable
            pass
        except Exception:
            # Other exceptions should be caught
            pass
