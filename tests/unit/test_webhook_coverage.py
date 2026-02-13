"""
Coverage tests for src/webhook.py.

Targets the ~86 missed lines covering:
- WebhookHandler: init edge cases, fallback to default webhook
- validate_webhook: body reading errors, query param edge cases, validator exceptions
- process_webhook: blob data type, chain processing, retry, module errors
- _process_chain: chain validation, execution, task queue full
- _get_cleaned_data: credential cleanup success/failure
- TaskManager: validation, task creation, cleanup, metrics
"""

import pytest
import asyncio
import json
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException, Request
from starlette.testclient import TestClient


def make_mock_request(
    body=b'{"key":"value"}',
    headers=None,
    query_params=None,
):
    """Helper to create a mock Request object."""
    mock_request = MagicMock(spec=Request)
    mock_request.body = AsyncMock(return_value=body)
    mock_request.headers = headers or {
        "content-type": "application/json",
        "host": "localhost",
    }
    if query_params is None:
        mock_request.query_params = {}
    else:
        mock_request.query_params = query_params
    return mock_request


# ============================================================================
# TaskManager tests
# ============================================================================


class TestTaskManager:
    """Test TaskManager edge cases."""

    def test_task_manager_invalid_max_concurrent_type(self):
        """Test TaskManager rejects non-int max_concurrent_tasks."""
        from src.webhook import TaskManager

        with pytest.raises(ValueError, match="must be an integer"):
            TaskManager(max_concurrent_tasks="100")

    def test_task_manager_max_concurrent_below_minimum(self):
        """Test TaskManager rejects max_concurrent below minimum."""
        from src.webhook import TaskManager

        with pytest.raises(ValueError, match="must be >="):
            TaskManager(max_concurrent_tasks=0)

    def test_task_manager_max_concurrent_above_limit(self):
        """Test TaskManager rejects max_concurrent above security limit."""
        from src.webhook import TaskManager

        with pytest.raises(ValueError, match="exceeds security limit"):
            TaskManager(max_concurrent_tasks=100000)

    def test_task_manager_invalid_timeout_type(self):
        """Test TaskManager rejects non-numeric timeout."""
        from src.webhook import TaskManager

        with pytest.raises(ValueError, match="must be a number"):
            TaskManager(task_timeout="invalid")

    def test_task_manager_timeout_below_minimum(self):
        """Test TaskManager rejects timeout below minimum."""
        from src.webhook import TaskManager

        with pytest.raises(ValueError, match="must be >="):
            TaskManager(task_timeout=0.01)

    def test_task_manager_timeout_above_limit(self):
        """Test TaskManager rejects timeout above security limit."""
        from src.webhook import TaskManager

        with pytest.raises(ValueError, match="exceeds security limit"):
            TaskManager(task_timeout=7200.0)

    @pytest.mark.asyncio
    async def test_create_task_invalid_timeout(self):
        """Test create_task rejects invalid timeout type."""
        from src.webhook import TaskManager

        tm = TaskManager(max_concurrent_tasks=10, task_timeout=10.0)

        with pytest.raises(ValueError, match="must be a number"):
            await tm.create_task(asyncio.sleep(0), timeout="invalid")

    @pytest.mark.asyncio
    async def test_create_task_timeout_below_minimum(self):
        """Test create_task rejects timeout below minimum."""
        from src.webhook import TaskManager

        tm = TaskManager(max_concurrent_tasks=10, task_timeout=10.0)

        with pytest.raises(ValueError, match="must be >="):
            await tm.create_task(asyncio.sleep(0), timeout=0.01)

    @pytest.mark.asyncio
    async def test_create_task_timeout_above_maximum(self):
        """Test create_task rejects timeout above security limit."""
        from src.webhook import TaskManager

        tm = TaskManager(max_concurrent_tasks=10, task_timeout=10.0)

        with pytest.raises(ValueError, match="exceeds security limit"):
            await tm.create_task(asyncio.sleep(0), timeout=7200.0)

    @pytest.mark.asyncio
    async def test_create_task_success(self):
        """Test create_task creates and tracks task."""
        from src.webhook import TaskManager

        tm = TaskManager(max_concurrent_tasks=10, task_timeout=10.0)

        async def dummy():
            return "done"

        task = await tm.create_task(dummy())
        result = await task
        assert result == "done"

    @pytest.mark.asyncio
    async def test_create_task_timeout_triggers(self):
        """Test create_task timeout raises exception."""
        from src.webhook import TaskManager

        tm = TaskManager(max_concurrent_tasks=10, task_timeout=10.0)

        async def slow():
            await asyncio.sleep(100)

        task = await tm.create_task(slow(), timeout=0.1)
        with pytest.raises(Exception, match="exceeded timeout"):
            await task

    def test_get_metrics(self):
        """Test get_metrics returns correct format."""
        from src.webhook import TaskManager

        tm = TaskManager(max_concurrent_tasks=50, task_timeout=10.0)
        metrics = tm.get_metrics()

        assert metrics["max_concurrent_tasks"] == 50
        assert metrics["active_tasks"] == 0
        assert metrics["total_tasks_created"] == 0
        assert metrics["queue_usage_percent"] == 0.0

    def test_cleanup_completed_tasks(self):
        """Test _cleanup_completed_tasks removes done tasks."""
        from src.webhook import TaskManager

        tm = TaskManager(max_concurrent_tasks=10, task_timeout=10.0)

        mock_task_done = MagicMock()
        mock_task_done.done.return_value = True
        mock_task_active = MagicMock()
        mock_task_active.done.return_value = False

        tm.active_tasks = {mock_task_done, mock_task_active}
        tm._cleanup_completed_tasks()

        assert mock_task_done not in tm.active_tasks
        assert mock_task_active in tm.active_tasks


# ============================================================================
# WebhookHandler tests
# ============================================================================


class TestWebhookHandlerInit:
    """Test WebhookHandler initialization edge cases."""

    def test_init_webhook_not_found_no_default(self):
        """Test init raises 404 when webhook ID not found and no default."""
        from src.webhook import WebhookHandler

        with pytest.raises(HTTPException) as exc_info:
            WebhookHandler(
                "nonexistent",
                {"other_webhook": {"module": "log"}},
                {},
                make_mock_request(),
            )
        assert exc_info.value.status_code == 404

    def test_init_fallback_to_default(self):
        """Test init falls back to default webhook when ID not found."""
        from src.webhook import WebhookHandler

        handler = WebhookHandler(
            "nonexistent",
            {"default": {"data_type": "json", "module": "log"}},
            {},
            make_mock_request(),
        )
        assert handler.config == {"data_type": "json", "module": "log"}

    def test_init_invalid_webhook_id(self):
        """Test init rejects invalid webhook ID."""
        from src.webhook import WebhookHandler

        with pytest.raises(HTTPException) as exc_info:
            WebhookHandler(
                "../../../etc/passwd",
                {"test": {"module": "log"}},
                {},
                make_mock_request(),
            )
        assert exc_info.value.status_code == 400

    def test_init_config_not_dict(self):
        """Test init rejects non-dict config."""
        from src.webhook import WebhookHandler

        with pytest.raises(HTTPException) as exc_info:
            WebhookHandler(
                "test",
                {"test": "not-a-dict"},
                {},
                make_mock_request(),
            )
        assert exc_info.value.status_code == 500

    def test_init_with_validators(self):
        """Test init creates validators for configured auth methods."""
        from src.webhook import WebhookHandler

        config = {
            "test_wh": {
                "data_type": "json",
                "module": "log",
                "authorization": "Bearer test-token",
            }
        }
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        assert len(handler.validators) == 1

    def test_init_with_namespace(self):
        """Test init stores namespace."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request(), namespace="staging"
        )
        assert handler.namespace == "staging"


class TestValidateWebhook:
    """Test WebhookHandler.validate_webhook method."""

    @pytest.mark.asyncio
    async def test_validate_body_read_error(self):
        """Test validate_webhook handles body read errors."""
        from src.webhook import WebhookHandler

        mock_request = make_mock_request()
        mock_request.body = AsyncMock(side_effect=Exception("Read error"))

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler("test_wh", config, {}, mock_request)

        is_valid, message = await handler.validate_webhook()
        assert is_valid is False
        assert "Failed to read request body" in message

    @pytest.mark.asyncio
    async def test_validate_no_validators(self):
        """Test validate_webhook passes when no validators configured."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        is_valid, message = await handler.validate_webhook()
        assert is_valid is True
        assert message == "Valid webhook"

    @pytest.mark.asyncio
    async def test_validate_validator_returns_non_bool(self):
        """Test validate_webhook handles validator returning non-boolean is_valid."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        # Add a mock validator that returns non-boolean
        mock_validator = MagicMock()
        mock_validator.validate = AsyncMock(return_value=(1, "OK"))
        handler.validators = [mock_validator]

        is_valid, message = await handler.validate_webhook()
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_validator_returns_non_string_message(self):
        """Test validate_webhook handles validator returning non-string message."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        # Add a mock validator that returns non-string message but fails
        mock_validator = MagicMock()
        mock_validator.validate = AsyncMock(return_value=(False, None))
        handler.validators = [mock_validator]

        is_valid, message = await handler.validate_webhook()
        assert is_valid is False
        assert message == "Validation failed"

    @pytest.mark.asyncio
    async def test_validate_validator_exception(self):
        """Test validate_webhook handles validator exception."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        mock_validator = MagicMock()
        mock_validator.validate = AsyncMock(side_effect=Exception("Validator crash"))
        handler.validators = [mock_validator]

        is_valid, message = await handler.validate_webhook()
        assert is_valid is False


class TestProcessWebhook:
    """Test WebhookHandler.process_webhook method."""

    @pytest.mark.asyncio
    async def test_process_blob_data_type(self):
        """Test process_webhook with blob data type."""
        from src.webhook import WebhookHandler

        body = b"raw binary data"
        config = {"test_wh": {"data_type": "blob", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request(body=body)
        )
        handler._cached_body = body

        with patch("src.webhook.task_manager") as mock_tm:
            mock_tm.create_task = AsyncMock(return_value=MagicMock())
            result = await handler.process_webhook()

        payload, headers, task = result
        assert payload == body

    @pytest.mark.asyncio
    async def test_process_unsupported_data_type(self):
        """Test process_webhook rejects unsupported data type."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "xml", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b"<xml>data</xml>"

        with pytest.raises(HTTPException) as exc_info:
            await handler.process_webhook()
        assert exc_info.value.status_code == 415

    @pytest.mark.asyncio
    async def test_process_malformed_json(self):
        """Test process_webhook rejects malformed JSON."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request(body=b"not json")
        )
        handler._cached_body = b"not json"

        with pytest.raises(HTTPException) as exc_info:
            await handler.process_webhook()
        assert exc_info.value.status_code == 400
        assert "Malformed JSON" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_process_non_string_data_type(self):
        """Test process_webhook rejects non-string data_type."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": 123, "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with pytest.raises(HTTPException) as exc_info:
            await handler.process_webhook()
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_process_missing_module(self):
        """Test process_webhook raises error when module is missing."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with pytest.raises(HTTPException) as exc_info:
            await handler.process_webhook()
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_process_non_string_module_name(self):
        """Test process_webhook rejects non-string module name."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": 123}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with pytest.raises(HTTPException) as exc_info:
            await handler.process_webhook()
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_process_unknown_module(self):
        """Test process_webhook rejects unknown module name."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "nonexistent_module"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with pytest.raises(HTTPException) as exc_info:
            await handler.process_webhook()
        assert exc_info.value.status_code == 501

    @pytest.mark.asyncio
    async def test_process_module_instantiation_failure(self):
        """Test process_webhook handles module instantiation error."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with patch("src.webhook.ModuleRegistry.get") as mock_reg:
            mock_module_class = MagicMock()
            mock_module_class.side_effect = Exception("Module init failed")
            mock_reg.return_value = mock_module_class

            with pytest.raises(HTTPException) as exc_info:
                await handler.process_webhook()
            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_process_with_retry_enabled(self):
        """Test process_webhook with retry enabled creates tracked task."""
        from src.webhook import WebhookHandler

        config = {
            "test_wh": {
                "data_type": "json",
                "module": "log",
                "retry": {"enabled": True, "max_attempts": 3},
            }
        }
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        mock_task = MagicMock()

        with patch("src.webhook.ModuleRegistry.get") as mock_reg, patch(
            "src.webhook.task_manager"
        ) as mock_tm:
            mock_module_class = MagicMock()
            mock_module_instance = MagicMock()
            mock_module_instance.process = AsyncMock()
            mock_module_class.return_value = mock_module_instance
            mock_reg.return_value = mock_module_class
            mock_tm.create_task = AsyncMock(return_value=mock_task)

            payload, headers, task = await handler.process_webhook()
            assert task is mock_task

    @pytest.mark.asyncio
    async def test_process_with_retry_task_queue_full(self):
        """Test process_webhook handles full task queue when retry is enabled."""
        from src.webhook import WebhookHandler

        config = {
            "test_wh": {
                "data_type": "json",
                "module": "log",
                "retry": {"enabled": True, "max_attempts": 3},
            }
        }
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with patch("src.webhook.ModuleRegistry.get") as mock_reg, patch(
            "src.webhook.task_manager"
        ) as mock_tm:
            mock_module_class = MagicMock()
            mock_module_instance = MagicMock()
            mock_module_instance.process = AsyncMock()
            mock_module_class.return_value = mock_module_instance
            mock_reg.return_value = mock_module_class
            mock_tm.create_task = AsyncMock(side_effect=Exception("Queue full"))

            payload, headers, task = await handler.process_webhook()
            assert task is None  # Task was not created

    @pytest.mark.asyncio
    async def test_process_no_retry_task_queue_full(self):
        """Test process_webhook handles full task queue when no retry."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with patch("src.webhook.ModuleRegistry.get") as mock_reg, patch(
            "src.webhook.task_manager"
        ) as mock_tm:
            mock_module_class = MagicMock()
            mock_module_instance = MagicMock()
            mock_module_instance.process = AsyncMock()
            mock_module_class.return_value = mock_module_instance
            mock_reg.return_value = mock_module_class
            mock_tm.create_task = AsyncMock(side_effect=Exception("Queue full"))

            payload, headers, task = await handler.process_webhook()
            assert task is None

    @pytest.mark.asyncio
    async def test_process_with_connection_injection(self):
        """Test process_webhook injects connection_details from connection_config."""
        from src.webhook import WebhookHandler

        config = {
            "test_wh": {
                "data_type": "json",
                "module": "log",
                "connection": "my_db",
            }
        }
        conn_config = {
            "my_db": {"type": "postgresql", "host": "db.example.com", "port": 5432}
        }

        handler = WebhookHandler(
            "test_wh", config, conn_config, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with patch("src.webhook.ModuleRegistry.get") as mock_reg, patch(
            "src.webhook.task_manager"
        ) as mock_tm:
            mock_module_class = MagicMock()
            mock_module_instance = MagicMock()
            mock_module_instance.process = AsyncMock()
            mock_module_class.return_value = mock_module_instance
            mock_reg.return_value = mock_module_class
            mock_tm.create_task = AsyncMock(return_value=MagicMock())

            await handler.process_webhook()

            # Verify module was instantiated with connection_details
            call_args = mock_module_class.call_args
            module_config = call_args[0][0]
            assert "connection_details" in module_config


class TestProcessChain:
    """Test WebhookHandler._process_chain method."""

    @pytest.mark.asyncio
    async def test_process_chain_invalid_config(self):
        """Test _process_chain with invalid chain configuration."""
        from src.webhook import WebhookHandler

        config = {
            "test_wh": {
                "data_type": "json",
                "chain": "not_a_list",
            }
        }
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )
        handler._cached_body = b'{"key":"value"}'

        with pytest.raises(HTTPException) as exc_info:
            await handler._process_chain({"key": "value"}, {})
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_process_chain_success(self):
        """Test _process_chain with valid chain configuration."""
        from src.webhook import WebhookHandler

        config = {
            "test_wh": {
                "data_type": "json",
                "chain": ["log"],
                "chain-config": {"execution": "sequential"},
            }
        }
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        with patch("src.webhook.task_manager") as mock_tm:
            mock_tm.create_task = AsyncMock(return_value=MagicMock())
            payload, headers, task = await handler._process_chain(
                {"key": "value"}, {"content-type": "application/json"}
            )

        assert payload == {"key": "value"}

    @pytest.mark.asyncio
    async def test_process_chain_task_queue_full(self):
        """Test _process_chain handles full task queue."""
        from src.webhook import WebhookHandler

        config = {
            "test_wh": {
                "data_type": "json",
                "chain": ["log"],
                "chain-config": {"execution": "sequential"},
            }
        }
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        with patch("src.webhook.task_manager") as mock_tm:
            mock_tm.create_task = AsyncMock(side_effect=Exception("Queue full"))
            payload, headers, task = await handler._process_chain(
                {"key": "value"}, {"content-type": "application/json"}
            )

        assert task is None


class TestGetCleanedData:
    """Test WebhookHandler._get_cleaned_data method."""

    def test_cleanup_disabled(self):
        """Test _get_cleaned_data returns original data when cleanup is disabled."""
        from src.webhook import WebhookHandler

        config = {
            "test_wh": {
                "data_type": "json",
                "module": "log",
                "credential_cleanup": {"enabled": False},
            }
        }
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        payload = {"password": "secret"}
        headers = {"Authorization": "Bearer token"}
        cleaned_payload, cleaned_headers = handler._get_cleaned_data(payload, headers)

        assert cleaned_payload == payload
        assert cleaned_headers == headers

    def test_cleanup_enabled_default(self):
        """Test _get_cleaned_data with default cleanup enabled."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        payload = {"username": "admin", "password": "secret"}
        headers = {"Authorization": "Bearer token", "Content-Type": "application/json"}
        cleaned_payload, cleaned_headers = handler._get_cleaned_data(payload, headers)

        # Should have cleaned credentials
        assert isinstance(cleaned_payload, dict)
        assert isinstance(cleaned_headers, dict)

    def test_cleanup_exception_returns_original(self):
        """Test _get_cleaned_data returns original data on cleanup exception."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        payload = {"data": "test"}
        headers = {"Content-Type": "application/json"}

        with patch("src.utils.CredentialCleaner") as mock_cleaner_cls:
            mock_cleaner_cls.side_effect = Exception("Cleanup error")
            cleaned_payload, cleaned_headers = handler._get_cleaned_data(
                payload, headers
            )

        assert cleaned_payload == payload
        assert cleaned_headers == headers

    def test_cleanup_non_dict_payload(self):
        """Test _get_cleaned_data with non-dict payload (string)."""
        from src.webhook import WebhookHandler

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler(
            "test_wh", config, {}, make_mock_request()
        )

        payload = "raw string payload"
        headers = {"Content-Type": "text/plain"}
        cleaned_payload, cleaned_headers = handler._get_cleaned_data(payload, headers)

        # String payload should pass through unchanged
        assert cleaned_payload == "raw string payload"


class TestProcessWebhookBodyReading:
    """Test process_webhook body reading paths."""

    @pytest.mark.asyncio
    async def test_process_webhook_body_read_error(self):
        """Test process_webhook handles body read error when not cached."""
        from src.webhook import WebhookHandler

        mock_request = make_mock_request()
        mock_request.body = AsyncMock(side_effect=Exception("Read error"))

        config = {"test_wh": {"data_type": "json", "module": "log"}}
        handler = WebhookHandler("test_wh", config, {}, mock_request)
        # Don't set _cached_body to force reading

        with pytest.raises(HTTPException) as exc_info:
            await handler.process_webhook()
        assert exc_info.value.status_code == 400
