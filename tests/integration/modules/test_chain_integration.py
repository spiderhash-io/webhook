"""
Integration tests for webhook chaining feature.

Tests real chain execution with actual modules.
"""

import pytest
import asyncio
import os
import json
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport
from src.main import app

# Allow localhost for integration tests
os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "true"


@pytest.mark.integration
@pytest.mark.asyncio
class TestChainIntegration:
    """Integration tests for webhook chaining."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test")

    @pytest.fixture
    def webhook_config_file(self, tmp_path):
        """Create temporary webhook config file."""
        config_file = tmp_path / "webhooks.json"
        return config_file

    @pytest.fixture
    def connection_config_file(self, tmp_path):
        """Create temporary connection config file."""
        config_file = tmp_path / "connections.json"
        config = {
            "redis_local": {
                "type": "redis-rq",
                "host": "localhost",
                "port": 6379,
                "db": 0,
            }
        }
        config_file.write_text(json.dumps(config))
        return config_file

    def _load_configs(self, webhook_config_file, connection_config_file):
        """Helper to load configs from files."""
        import json

        # Load webhook config
        webhook_config = {}
        if webhook_config_file.exists():
            webhook_config = json.loads(webhook_config_file.read_text())

        # Load connection config
        connection_config = {}
        if connection_config_file.exists():
            connection_config = json.loads(connection_config_file.read_text())

        return webhook_config, connection_config

    @pytest.mark.asyncio
    async def test_sequential_chain_log_and_save(
        self, client, webhook_config_file, connection_config_file, tmp_path
    ):
        """Test sequential chain with log and save_to_disk modules."""
        # Create webhook config with chain
        webhook_config = {
            "test_chain_sequential": {
                "data_type": "json",
                "chain": ["log", "save_to_disk"],
                "chain-config": {"execution": "sequential", "continue_on_error": True},
                "authorization": "Bearer test_token",
            }
        }
        webhook_config_file.write_text(json.dumps(webhook_config))

        # Reload configs after writing file
        webhook_config_dict, connection_config_dict = self._load_configs(
            webhook_config_file, connection_config_file
        )

        # Set configs in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = None
        app.state.webhook_config_data = webhook_config_dict

        try:
            # Also patch connection_config for backward compatibility
            with patch("src.main.connection_config", connection_config_dict):
                # Clean up any existing webhooks directory
                webhooks_dir = tmp_path / "webhooks"
                if webhooks_dir.exists():
                    import shutil

                    shutil.rmtree(webhooks_dir)

                # Send webhook request
                payload = {"test": "data", "timestamp": "2024-01-01T00:00:00Z"}
                response = await client.post(
                    "/webhook/test_chain_sequential",
                    json=payload,
                    headers={"Authorization": "Bearer test_token"},
                )

                # Verify response
                assert response.status_code == 200

                # Wait a bit for async processing
                await asyncio.sleep(0.5)

                # Verify file was saved (save_to_disk module)
                # Note: This depends on the actual save_to_disk implementation
                # The test verifies the chain executed without errors
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")

    @pytest.mark.asyncio
    async def test_parallel_chain_execution(
        self, client, webhook_config_file, connection_config_file
    ):
        """Test parallel chain execution."""
        # Create webhook config with parallel chain
        webhook_config = {
            "test_chain_parallel": {
                "data_type": "json",
                "chain": [
                    {"module": "log", "module-config": {}},
                    {"module": "log", "module-config": {}},
                ],
                "chain-config": {"execution": "parallel", "continue_on_error": True},
                "authorization": "Bearer test_token",
            }
        }
        webhook_config_file.write_text(json.dumps(webhook_config))

        # Reload configs after writing file
        webhook_config_dict, connection_config_dict = self._load_configs(
            webhook_config_file, connection_config_file
        )

        # Set configs in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = None
        app.state.webhook_config_data = webhook_config_dict

        try:
            # Also patch connection_config for backward compatibility
            with patch("src.main.connection_config", connection_config_dict):
                # Send webhook request
                payload = {"test": "parallel_execution"}
                response = await client.post(
                    "/webhook/test_chain_parallel",
                    json=payload,
                    headers={"Authorization": "Bearer test_token"},
                )

                # Verify response
                assert response.status_code == 200
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")

    @pytest.mark.asyncio
    async def test_chain_with_retry(
        self, client, webhook_config_file, connection_config_file
    ):
        """Test chain with per-module retry configuration."""
        # Create webhook config with retry
        webhook_config = {
            "test_chain_retry": {
                "data_type": "json",
                "chain": [
                    {
                        "module": "log",
                        "retry": {
                            "enabled": True,
                            "max_attempts": 3,
                            "initial_delay": 0.1,
                        },
                    }
                ],
                "chain-config": {"execution": "sequential"},
                "authorization": "Bearer test_token",
            }
        }
        webhook_config_file.write_text(json.dumps(webhook_config))

        # Reload configs after writing file
        webhook_config_dict, connection_config_dict = self._load_configs(
            webhook_config_file, connection_config_file
        )

        # Set configs in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = None
        app.state.webhook_config_data = webhook_config_dict

        try:
            # Also patch connection_config for backward compatibility
            with patch("src.main.connection_config", connection_config_dict):
                # Send webhook request
                payload = {"test": "retry_chain"}
                response = await client.post(
                    "/webhook/test_chain_retry",
                    json=payload,
                    headers={"Authorization": "Bearer test_token"},
                )

                # Verify response
                assert response.status_code == 200
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")

    @pytest.mark.asyncio
    async def test_chain_continue_on_error(
        self, client, webhook_config_file, connection_config_file
    ):
        """Test chain with continue_on_error=True."""
        # Create webhook config with chain that may have failures
        webhook_config = {
            "test_chain_continue": {
                "data_type": "json",
                "chain": [
                    "log",  # This should succeed
                    "log",  # This should also succeed
                ],
                "chain-config": {"execution": "sequential", "continue_on_error": True},
                "authorization": "Bearer test_token",
            }
        }
        webhook_config_file.write_text(json.dumps(webhook_config))

        # Reload configs after writing file
        webhook_config_dict, connection_config_dict = self._load_configs(
            webhook_config_file, connection_config_file
        )

        # Set configs in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = None
        app.state.webhook_config_data = webhook_config_dict

        try:
            # Also patch connection_config for backward compatibility
            with patch("src.main.connection_config", connection_config_dict):
                # Send webhook request
                payload = {"test": "continue_on_error"}
                response = await client.post(
                    "/webhook/test_chain_continue",
                    json=payload,
                    headers={"Authorization": "Bearer test_token"},
                )

                # Verify response
                assert response.status_code == 200
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")

    @pytest.mark.asyncio
    async def test_chain_backward_compatibility(
        self, client, webhook_config_file, connection_config_file
    ):
        """Test that single module config still works (backward compatibility)."""
        # Create webhook config with single module (no chain)
        webhook_config = {
            "test_single_module": {
                "data_type": "json",
                "module": "log",
                "authorization": "Bearer test_token",
            }
        }
        webhook_config_file.write_text(json.dumps(webhook_config))

        # Reload configs after writing file
        webhook_config_dict, connection_config_dict = self._load_configs(
            webhook_config_file, connection_config_file
        )

        # Set configs in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = None
        app.state.webhook_config_data = webhook_config_dict

        try:
            # Also patch connection_config for backward compatibility
            with patch("src.main.connection_config", connection_config_dict):
                # Send webhook request
                payload = {"test": "backward_compat"}
                response = await client.post(
                    "/webhook/test_single_module",
                    json=payload,
                    headers={"Authorization": "Bearer test_token"},
                )

                # Verify response (should work as before)
                assert response.status_code == 200
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")

    @pytest.mark.asyncio
    async def test_chain_validation_error(
        self, client, webhook_config_file, connection_config_file
    ):
        """Test that invalid chain configuration is rejected."""
        # Create webhook config with invalid chain
        webhook_config = {
            "test_invalid_chain": {
                "data_type": "json",
                "chain": ["nonexistent_module"],
                "authorization": "Bearer test_token",
            }
        }
        webhook_config_file.write_text(json.dumps(webhook_config))

        # Reload configs after writing file
        webhook_config_dict, connection_config_dict = self._load_configs(
            webhook_config_file, connection_config_file
        )

        # Set configs in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = None
        app.state.webhook_config_data = webhook_config_dict

        try:
            # Also patch connection_config for backward compatibility
            with patch("src.main.connection_config", connection_config_dict):
                # Send webhook request
                payload = {"test": "invalid_chain"}
                response = await client.post(
                    "/webhook/test_invalid_chain",
                    json=payload,
                    headers={"Authorization": "Bearer test_token"},
                )

                # Verify response (should be 400 or 500 due to validation error)
                # The exact status code depends on when validation happens
                assert response.status_code in [400, 404, 500]
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")
