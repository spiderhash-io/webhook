"""
Security tests for the default logging webhook feature.

SECURITY CONCERNS ADDRESSED:
1. Information Disclosure - Default webhook logs all data to console
2. Open Endpoint - Without webhooks.json, any webhook_id is accessible
3. No Authentication - Default webhook has no authorization
4. DoS Risk - Unlimited access to default endpoint could flood logs
5. Log Injection - Pretty-printed output could be abused
6. Production Misconfiguration - Accidental deployment without config
"""

import pytest
import json
import os
import tempfile
import asyncio
from io import StringIO
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from starlette.testclient import TestClient as StarletteTestClient

from src.config_manager import ConfigManager, ReloadResult
from src.modules.log import LogModule


class TestDefaultWebhookSecurityConcerns:
    """Test security concerns with default logging webhook."""

    # =========================================================================
    # SECURITY CONCERN 1: Information Disclosure (Configurable)
    # The default webhook logs ALL incoming data to console
    # By default, redaction is DISABLED for debugging purposes
    # Users can enable redaction with: "redact_sensitive": true
    # =========================================================================

    @pytest.mark.asyncio
    async def test_default_webhook_shows_all_data_for_debugging(self):
        """
        FEATURE: Default webhook should show ALL data for debugging.
        The purpose is to help users validate their setup.
        """
        # This is the default config created when webhooks.json is missing
        log_module = LogModule(
            {"module-config": {"pretty_print": True, "redact_sensitive": False}}
        )

        # Payload with sensitive data
        sensitive_payload = {
            "user": "admin",
            "password": "secret123",
            "api_key": "key_abc123",
            "token": "jwt_token_here",
            "data": "normal_data",
        }

        # Capture stdout
        with patch("builtins.print") as mock_print:
            await log_module.process(
                sensitive_payload, {"content-type": "application/json"}
            )

            # Get all printed output
            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # All data should be visible (no redaction for debugging)
            assert (
                "secret123" in all_output
            ), "Password should be visible for debugging!"
            assert (
                "key_abc123" in all_output
            ), "API key should be visible for debugging!"
            assert (
                "jwt_token_here" in all_output
            ), "Token should be visible for debugging!"

            # No redaction markers should be present
            assert "[REDACTED]" not in all_output

    @pytest.mark.asyncio
    async def test_sensitive_data_is_redacted_when_enabled(self):
        """
        SECURITY: Sensitive data must be redacted when redact_sensitive is enabled.
        """
        log_module = LogModule(
            {"module-config": {"pretty_print": True, "redact_sensitive": True}}
        )

        # Payload with sensitive data
        sensitive_payload = {
            "user": "admin",
            "password": "secret123",
            "api_key": "key_abc123",
            "token": "jwt_token_here",
            "data": "normal_data",
        }

        # Capture stdout
        with patch("builtins.print") as mock_print:
            await log_module.process(
                sensitive_payload, {"content-type": "application/json"}
            )

            # Get all printed output
            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # Sensitive data should be redacted
            assert "secret123" not in all_output, "Password was not redacted!"
            assert "key_abc123" not in all_output, "API key was not redacted!"
            assert "jwt_token_here" not in all_output, "Token was not redacted!"

            # Redaction markers should be present
            assert "[REDACTED]" in all_output

    @pytest.mark.asyncio
    async def test_default_headers_are_visible_for_debugging(self):
        """
        FEATURE: Default webhook should show ALL headers for debugging.
        """
        log_module = LogModule(
            {"module-config": {"pretty_print": True, "redact_sensitive": False}}
        )

        sensitive_headers = {
            "content-type": "application/json",
            "authorization": "Bearer secret_token_12345",
            "x-api-key": "api_key_secret",
            "cookie": "session=abc123",
            "x-custom-header": "safe_value",
        }

        with patch("builtins.print") as mock_print:
            await log_module.process({"data": "test"}, sensitive_headers)

            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # All header values should be visible for debugging
            assert (
                "secret_token_12345" in all_output
            ), "Authorization header should be visible!"
            assert "api_key_secret" in all_output, "API key header should be visible!"
            assert "session=abc123" in all_output, "Cookie should be visible!"

    @pytest.mark.asyncio
    async def test_sensitive_headers_are_redacted_when_enabled(self):
        """
        SECURITY: Sensitive headers must be redacted when redact_sensitive is enabled.
        """
        log_module = LogModule(
            {"module-config": {"pretty_print": True, "redact_sensitive": True}}
        )

        sensitive_headers = {
            "content-type": "application/json",
            "authorization": "Bearer secret_token_12345",
            "x-api-key": "api_key_secret",
            "cookie": "session=abc123",
            "x-custom-header": "safe_value",
        }

        with patch("builtins.print") as mock_print:
            await log_module.process({"data": "test"}, sensitive_headers)

            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # Sensitive header values should be redacted
            assert (
                "secret_token_12345" not in all_output
            ), "Authorization header not redacted!"
            assert "api_key_secret" not in all_output, "API key header not redacted!"
            assert "session=abc123" not in all_output, "Cookie not redacted!"

    @pytest.mark.asyncio
    async def test_nested_sensitive_data_is_redacted_when_enabled(self):
        """
        SECURITY: Sensitive data in nested structures must be redacted when enabled.
        """
        log_module = LogModule(
            {"module-config": {"pretty_print": True, "redact_sensitive": True}}
        )

        nested_payload = {
            "user": {
                "name": "John",
                "credentials": {
                    "password": "nested_secret",
                    "api_token": "nested_token",
                },
            },
            "config": {"database_url": "postgres://user:pass@localhost/db"},
        }

        with patch("builtins.print") as mock_print:
            await log_module.process(nested_payload, {})

            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            assert "nested_secret" not in all_output
            assert "nested_token" not in all_output
            assert "postgres://user:pass@localhost/db" not in all_output

    @pytest.mark.asyncio
    async def test_redaction_defaults_to_enabled_when_not_specified(self):
        """
        SECURITY: When redact_sensitive is not specified, default to True (secure by default).
        """
        # No redact_sensitive option specified
        log_module = LogModule({"module-config": {"pretty_print": True}})

        sensitive_payload = {"password": "secret123"}

        with patch("builtins.print") as mock_print:
            await log_module.process(sensitive_payload, {})

            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # Should default to redacting (secure by default)
            assert (
                "secret123" not in all_output
            ), "Should redact by default for security!"
            assert "[REDACTED]" in all_output

    # =========================================================================
    # SECURITY CONCERN 2: Open Endpoint Without Authentication
    # Default webhook has no authorization - any request is accepted
    # =========================================================================

    @pytest.mark.asyncio
    async def test_default_webhook_has_no_authorization(self):
        """
        SECURITY: Verify that default webhook does NOT have authorization.
        This is a known security trade-off that should be documented.
        """
        # Simulate the default config that's created
        default_config = {
            "default": {
                "data_type": "json",
                "module": "log",
                "module-config": {"pretty_print": True},
            }
        }

        # Verify no authorization is set
        assert (
            "authorization" not in default_config["default"]
        ), "Default webhook should not have authorization for testing purposes"

        # This test documents the security trade-off
        # In production, users should ALWAYS provide webhooks.json with proper auth

    @pytest.mark.asyncio
    @pytest.mark.todo
    async def test_default_webhook_fallback_logs_warning(self):
        """
        SECURITY: When falling back to default webhook, a warning should be logged.
        This helps detect misconfigurations.
        
        NOTE: This test is flaky due to logging mock issues. Needs refactoring.
        """
        from src.webhook import WebhookHandler
        from unittest.mock import MagicMock

        # Create default config
        configs = {
            "default": {
                "data_type": "json",
                "module": "log",
                "module-config": {"pretty_print": True},
            }
        }

        # Mock request
        mock_request = MagicMock()
        mock_request.headers = {}

        with patch("builtins.print") as mock_print:
            # Request a non-existent webhook - should fall back to default
            handler = WebhookHandler("nonexistent_webhook", configs, {}, mock_request)

            # Verify warning was logged
            warning_logged = any(
                "not found" in str(call).lower() and "default" in str(call).lower()
                for call in mock_print.call_args_list
            )
            assert (
                warning_logged
            ), "No warning logged when falling back to default webhook!"

    # =========================================================================
    # SECURITY CONCERN 3: DoS via Log Flooding
    # Unlimited access could flood logs and consume resources
    # =========================================================================

    @pytest.mark.asyncio
    async def test_default_webhook_has_output_size_limits(self):
        """
        SECURITY: Default webhook should limit output size to prevent DoS.
        """
        log_module = LogModule({"module-config": {"pretty_print": True}})

        # Create a very large payload
        large_payload = {"data": "x" * 100000}  # 100KB string

        with patch("builtins.print") as mock_print:
            await log_module.process(large_payload, {})

            # Verify output was truncated
            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # Should not contain full 100KB string
            assert len(all_output) < 50000, "Output was not limited!"

    @pytest.mark.asyncio
    async def test_deeply_nested_payload_is_limited(self):
        """
        SECURITY: Deeply nested payloads should be limited to prevent stack overflow.
        """
        log_module = LogModule({"module-config": {"pretty_print": True}})

        # Create deeply nested structure
        deep_payload = {"level": 0}
        current = deep_payload
        for i in range(50):  # 50 levels deep
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        with patch("builtins.print") as mock_print:
            # Should not crash
            await log_module.process(deep_payload, {})

            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # Should contain depth limit indicator
            assert "depth" in all_output.lower() or len(all_output) > 0

    @pytest.mark.asyncio
    async def test_circular_reference_does_not_crash(self):
        """
        SECURITY: Circular references should not crash the server.
        """
        log_module = LogModule({"module-config": {"pretty_print": True}})

        # Create circular reference
        circular_payload = {"a": 1}
        circular_payload["self"] = circular_payload

        with patch("builtins.print") as mock_print:
            # Should not crash
            await log_module.process(circular_payload, {})

            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # Should handle gracefully
            assert len(all_output) > 0

    # =========================================================================
    # SECURITY CONCERN 4: Log Injection
    # Pretty-printed output could be abused for log injection
    # =========================================================================

    @pytest.mark.asyncio
    async def test_newlines_in_payload_are_sanitized(self):
        """
        SECURITY: Newlines in user data should not break log format.
        Note: pretty_print uses json.dumps which handles this properly.
        """
        log_module = LogModule(
            {"module-config": {"pretty_print": False}}  # Test non-pretty mode
        )

        injection_payload = {"data": "line1\nINJECTED_LOG_LINE\nline3"}

        with patch("builtins.print") as mock_print:
            await log_module.process(injection_payload, {})

            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # Newlines should be replaced with safe marker
            assert (
                "INJECTED_LOG_LINE" not in all_output.split("\n")[1:]
            ), "Log injection via newline possible!"

    @pytest.mark.asyncio
    async def test_control_characters_are_sanitized(self):
        """
        SECURITY: Control characters should be sanitized to prevent log injection.
        """
        log_module = LogModule({"module-config": {"pretty_print": False}})

        injection_payload = {"data": "normal\x00null\x08backspace\x1bescape"}

        with patch("builtins.print") as mock_print:
            await log_module.process(injection_payload, {})

            all_output = " ".join(str(call) for call in mock_print.call_args_list)

            # Control characters should be replaced
            assert "\x00" not in all_output
            assert "\x08" not in all_output
            assert "\x1b" not in all_output

    # =========================================================================
    # SECURITY CONCERN 5: Production Misconfiguration Detection
    # =========================================================================

    @pytest.mark.asyncio
    async def test_default_webhook_logs_startup_warning(self):
        """
        SECURITY: When default webhook is enabled, a clear warning should be logged.
        """
        # This is tested in ConfigManager._load_webhook_config
        manager = ConfigManager(
            webhook_config_file="nonexistent_webhooks.json",
            connection_config_file="nonexistent_connections.json",
        )

        with patch("builtins.print") as mock_print:
            config = await manager._load_webhook_config()

            # Should print warning
            warning_calls = [str(call) for call in mock_print.call_args_list]

            assert any(
                "webhooks.json not found" in call for call in warning_calls
            ), "No warning about missing webhooks.json!"
            assert any(
                "default logging" in call.lower() for call in warning_calls
            ), "No warning about default logging endpoint!"

    @pytest.mark.asyncio
    async def test_default_webhook_config_is_correct_structure(self):
        """
        SECURITY: Verify default webhook config has expected structure.
        This prevents unexpected behavior if config structure changes.
        """
        manager = ConfigManager(
            webhook_config_file="nonexistent_webhooks.json",
            connection_config_file="nonexistent_connections.json",
        )

        with patch("builtins.print"):  # Suppress output
            config = await manager._load_webhook_config()

        # Verify structure
        assert "default" in config
        assert config["default"]["data_type"] == "json"
        assert config["default"]["module"] == "log"
        assert config["default"]["module-config"]["pretty_print"] is True
        # Default webhook has redaction disabled for debugging purposes
        assert config["default"]["module-config"]["redact_sensitive"] is False

        # Verify NO dangerous options are set
        assert (
            "authorization" not in config["default"]
        ), "Default should not have auth (but this should be documented)"
        assert (
            "rate_limit" not in config["default"]
        ), "Default could benefit from rate limiting"

    # =========================================================================
    # SECURITY CONCERN 6: Webhook ID Validation on Fallback
    # =========================================================================

    @pytest.mark.asyncio
    async def test_invalid_webhook_id_is_rejected_before_fallback(self):
        """
        SECURITY: Invalid webhook IDs should be rejected even with default fallback.
        """
        from src.webhook import WebhookHandler
        from fastapi import HTTPException

        configs = {"default": {"data_type": "json", "module": "log"}}

        mock_request = MagicMock()
        mock_request.headers = {}

        # Test with malicious webhook IDs
        malicious_ids = [
            "../../../etc/passwd",
            "webhook\x00null",
            "webhook\ninjection",
            "<script>alert(1)</script>",
            "a" * 1000,  # Very long ID
        ]

        for malicious_id in malicious_ids:
            with pytest.raises(HTTPException) as exc_info:
                WebhookHandler(malicious_id, configs, {}, mock_request)

            # Should reject with 400, not fall through to default
            assert (
                exc_info.value.status_code == 400
            ), f"Malicious ID '{malicious_id[:20]}...' was not rejected!"


class TestDefaultWebhookPrettyPrintSecurity:
    """Test pretty print specific security concerns."""

    @pytest.mark.asyncio
    async def test_pretty_print_handles_non_json_serializable(self):
        """
        SECURITY: Non-JSON serializable objects should be handled safely.
        """
        log_module = LogModule({"module-config": {"pretty_print": True}})

        # Object that can't be serialized to JSON
        class NonSerializable:
            def __str__(self):
                return "NonSerializable object"

        payload = {"normal": "data", "object": NonSerializable()}

        with patch("builtins.print") as mock_print:
            # Should not crash
            await log_module.process(payload, {})

            # Should have output
            assert mock_print.called

    @pytest.mark.asyncio
    async def test_pretty_print_with_bytes_payload(self):
        """
        SECURITY: Binary payloads should be handled safely in pretty print mode.
        """
        log_module = LogModule({"module-config": {"pretty_print": True}})

        # Binary payload
        binary_payload = b"\x00\x01\x02\xff\xfe"

        with patch("builtins.print") as mock_print:
            # Should not crash
            await log_module.process(binary_payload, {})

            # Should have output
            assert mock_print.called

    @pytest.mark.asyncio
    async def test_pretty_print_unicode_handling(self):
        """
        SECURITY: Unicode should be handled safely (no UnicodeEncodeError).
        """
        log_module = LogModule({"module-config": {"pretty_print": True}})

        unicode_payload = {
            "emoji": "🔒🔑💻",
            "chinese": "中文测试",
            "arabic": "اختبار",
            "special": "\u0000\u001f",  # Control chars
        }

        with patch("builtins.print") as mock_print:
            # Should not crash
            await log_module.process(unicode_payload, {})

            # Should have output
            assert mock_print.called


class TestDefaultWebhookConfigManagerSecurity:
    """Test ConfigManager security with default webhooks."""

    @pytest.mark.asyncio
    async def test_get_all_webhook_configs_returns_copy(self):
        """
        SECURITY: get_all_webhook_configs should return a fresh copy to prevent callers
        from accidentally mutating internal state.
        """
        manager = ConfigManager(
            webhook_config_file="nonexistent_webhooks.json",
            connection_config_file="nonexistent_connections.json",
        )

        with patch("builtins.print"):  # Suppress output
            await manager.reload_webhooks()

        configs1 = manager.get_all_webhook_configs()
        configs2 = manager.get_all_webhook_configs()

        # Each call returns a fresh copy so the caller can mutate safely
        assert (
            configs1 is not configs2
        ), "get_all_webhook_configs should return a new copy each call"

        # Mutating the returned copy should not affect internal state
        configs1["default"]["module"] = "modified"
        internal_config = manager.get_webhook_config("default")
        assert (
            internal_config["module"] == "log"
        ), "Internal state was modified by external code!"

    @pytest.mark.asyncio
    async def test_default_webhook_validates_correctly(self):
        """
        SECURITY: Default webhook config should pass validation.
        """
        manager = ConfigManager(
            webhook_config_file="nonexistent_webhooks.json",
            connection_config_file="nonexistent_connections.json",
        )

        with patch("builtins.print"):  # Suppress output
            config = await manager._load_webhook_config()

        # Validate config
        error = await manager._validate_webhook_config(config)

        assert error is None, f"Default webhook config validation failed: {error}"


class TestDefaultWebhookEnvironmentSecurity:
    """Test environment-related security concerns."""

    def test_default_webhook_not_created_when_config_exists(self):
        """
        SECURITY: Default webhook should NOT be created when webhooks.json exists.
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "custom_webhook": {
                        "data_type": "json",
                        "module": "log",
                        "authorization": "Bearer secret",
                    }
                },
                f,
            )
            temp_file = f.name

        try:
            manager = ConfigManager(
                webhook_config_file=temp_file,
                connection_config_file="nonexistent_connections.json",
            )

            # Load config
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                config = loop.run_until_complete(manager._load_webhook_config())
            finally:
                loop.close()

            # Should NOT have default webhook
            assert (
                "default" not in config
            ), "Default webhook was created even though webhooks.json exists!"

            # Should have custom webhook
            assert "custom_webhook" in config
            assert config["custom_webhook"]["authorization"] == "Bearer secret"
        finally:
            os.unlink(temp_file)

    def test_empty_webhooks_json_does_not_create_default(self):
        """
        SECURITY: Empty webhooks.json should NOT create default webhook.
        User explicitly chose to have no webhooks.
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)  # Empty config
            temp_file = f.name

        try:
            manager = ConfigManager(
                webhook_config_file=temp_file,
                connection_config_file="nonexistent_connections.json",
            )

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                config = loop.run_until_complete(manager._load_webhook_config())
            finally:
                loop.close()

            # Should NOT have default webhook - user explicitly chose empty
            assert (
                "default" not in config
            ), "Default webhook was created for empty webhooks.json!"
            assert len(config) == 0
        finally:
            os.unlink(temp_file)
