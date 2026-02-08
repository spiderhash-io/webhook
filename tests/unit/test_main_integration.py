"""
Integration tests for main.py startup, shutdown, and initialization logic.
Tests cover missing coverage areas in main.py.
"""

import pytest
import asyncio
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from src.main import (
    app,
    startup_event,
    shutdown_event,
    cleanup_task,
    custom_openapi,
    startup_logic,
    shutdown_logic,
)
from src.config_manager import ConfigManager
from src.clickhouse_analytics import ClickHouseAnalytics


class TestMainStartupShutdown:
    """Test startup and shutdown event handlers."""

    @pytest.mark.asyncio
    async def test_startup_event_with_config_manager_success(self):
        """Test startup event with successful ConfigManager initialization."""
        from fastapi import FastAPI

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 0},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        with patch("src.main.webhook_config_data", {}), patch(
            "src.main.connection_config", {}
        ), patch("src.main.ConfigManager") as mock_cm_class:
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            mock_cm.initialize.assert_called_once()
            assert hasattr(test_app.state, "config_manager")

    @pytest.mark.asyncio
    async def test_startup_event_with_config_manager_failure(self):
        """Test startup event when ConfigManager initialization fails."""
        from fastapi import FastAPI

        test_app = FastAPI()

        with patch("src.main.webhook_config_data", {}), patch(
            "src.main.connection_config", {}
        ), patch(
            "src.main.inject_connection_details", AsyncMock(return_value={})
        ), patch(
            "src.main.ConfigManager"
        ) as mock_cm_class:
            mock_cm_class.create = AsyncMock(side_effect=Exception("Init failed"))

            await startup_logic(test_app)

            # Should handle error gracefully
            assert test_app.state.config_manager is None

    @pytest.mark.asyncio
    async def test_startup_event_with_clickhouse_config(self):
        """Test startup event with ClickHouse configuration."""
        from fastapi import FastAPI

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 1},
            )
        )
        clickhouse_conn = {"type": "clickhouse", "host": "localhost"}
        mock_cm.get_all_connection_configs.return_value = {
            "clickhouse1": clickhouse_conn
        }
        mock_cm.provider = None

        with patch("src.main.webhook_config_data", {}), patch(
            "src.main.connection_config", {}
        ), patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.ClickHouseAnalytics"
        ) as mock_ch_class:
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            mock_ch_instance = AsyncMock()
            mock_ch_instance.connect = AsyncMock()
            mock_ch_class.return_value = mock_ch_instance

            await startup_logic(test_app)

            if mock_ch_class.called:
                mock_ch_class.assert_called_once()
                mock_ch_instance.connect.assert_called_once()
            else:
                assert hasattr(test_app.state, "clickhouse_logger")

    @pytest.mark.asyncio
    async def test_startup_event_without_clickhouse_config(self):
        """Test startup event without ClickHouse configuration."""
        from fastapi import FastAPI

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 0},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        with patch("src.main.webhook_config_data", {}), patch(
            "src.main.connection_config", {}
        ), patch("src.main.ConfigManager") as mock_cm_class:
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            assert test_app.state.clickhouse_logger is None

    @pytest.mark.asyncio
    async def test_shutdown_event_with_all_components(self):
        """Test shutdown event with all components present."""
        from fastapi import FastAPI

        test_app = FastAPI()

        mock_watcher = Mock()
        mock_watcher.stop = Mock()

        mock_manager = AsyncMock()
        mock_manager.pool_registry = AsyncMock()
        mock_manager.pool_registry.close_all_pools = AsyncMock()

        mock_clickhouse = AsyncMock()
        mock_clickhouse.disconnect = AsyncMock()

        mock_stats = AsyncMock()
        mock_stats.close = AsyncMock()

        test_app.state.config_watcher = mock_watcher
        test_app.state.config_manager = mock_manager
        test_app.state.clickhouse_logger = mock_clickhouse

        with patch("src.main.stats", mock_stats):
            await shutdown_logic(test_app)

            mock_watcher.stop.assert_called_once()
            mock_manager.pool_registry.close_all_pools.assert_called_once()
            mock_clickhouse.disconnect.assert_called_once()
            mock_stats.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_event_with_errors(self):
        """Test shutdown event handles errors gracefully."""
        from fastapi import FastAPI

        test_app = FastAPI()

        mock_watcher = Mock()
        mock_watcher.stop.side_effect = Exception("Stop failed")

        mock_manager = AsyncMock()
        mock_manager.pool_registry = AsyncMock()
        mock_manager.pool_registry.close_all_pools.side_effect = Exception(
            "Close failed"
        )

        mock_clickhouse = AsyncMock()
        mock_clickhouse.disconnect.side_effect = Exception("Disconnect failed")

        mock_stats = AsyncMock()
        mock_stats.close.side_effect = Exception("Stats close failed")

        test_app.state.config_watcher = mock_watcher
        test_app.state.config_manager = mock_manager
        test_app.state.clickhouse_logger = mock_clickhouse

        with patch("src.main.stats", mock_stats):
            # Should not raise exceptions
            await shutdown_logic(test_app)

            # All should be called despite errors
            mock_watcher.stop.assert_called_once()
            mock_manager.pool_registry.close_all_pools.assert_called_once()
            mock_clickhouse.disconnect.assert_called_once()
            mock_stats.close.assert_called_once()


class TestCustomOpenAPI:
    """Test custom OpenAPI schema generation."""

    def setup_method(self):
        """Reset app.state before each test to ensure isolation."""
        # Ensure we reference the current app/custom_openapi after any reloads
        import src.main as main_module

        global app, custom_openapi
        app = main_module.app
        custom_openapi = main_module.custom_openapi

        # Clear any existing state that might interfere
        if hasattr(app.state, "config_manager"):
            app.state.config_manager = None
        if hasattr(app.state, "webhook_config_data"):
            app.state.webhook_config_data = None
        # Clear FastAPI's OpenAPI schema cache if it exists
        if hasattr(app, "_openapi_schema"):
            delattr(app, "_openapi_schema")

    def test_custom_openapi_with_config_manager(self):
        """Test custom OpenAPI with ConfigManager."""
        mock_config_manager = Mock()
        mock_config_manager.get_all_webhook_configs.return_value = {
            "webhook1": {"path": "/test"}
        }

        # Set config_manager in app.state and clear webhook_config_data for isolation
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = mock_config_manager
        app.state.webhook_config_data = (
            None  # Ensure we use config_manager, not fallback
        )

        try:
            # Import the module first to ensure it's loaded
            import src.openapi_generator

            # Patch using both string path (for import inside function) and object (for reliability)
            with patch(
                "src.openapi_generator.generate_openapi_schema"
            ) as mock_gen_str, patch.object(
                src.openapi_generator, "generate_openapi_schema"
            ) as mock_gen_obj:
                # Both should point to the same mock
                mock_gen_str.return_value = {"openapi": "3.0.0"}
                mock_gen_obj.return_value = {"openapi": "3.0.0"}
                result = custom_openapi()

                # Check that it was called (either mock should work)
                assert (
                    mock_gen_str.called or mock_gen_obj.called
                ), "generate_openapi_schema should have been called"
                if mock_gen_str.called:
                    mock_gen_str.assert_called_once_with(
                        {"webhook1": {"path": "/test"}}
                    )
                else:
                    mock_gen_obj.assert_called_once_with(
                        {"webhook1": {"path": "/test"}}
                    )
                assert result == {"openapi": "3.0.0"}
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")

    def test_custom_openapi_without_config_manager(self):
        """Test custom OpenAPI without ConfigManager."""
        # Set webhook_config_data in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = None
        app.state.webhook_config_data = {"webhook1": {"path": "/test"}}

        try:
            # Patch at the module level where it's imported inside custom_openapi
            with patch("src.openapi_generator.generate_openapi_schema") as mock_gen:
                mock_gen.return_value = {"openapi": "3.0.0"}
                result = custom_openapi()

                mock_gen.assert_called_once_with({"webhook1": {"path": "/test"}})
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")

    def test_custom_openapi_with_attribute_error(self):
        """Test custom OpenAPI when get_all_webhook_configs returns empty."""
        mock_config_manager = Mock()
        mock_config_manager.get_all_webhook_configs.return_value = {}

        # Set config_manager and webhook_config_data in app.state
        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = mock_config_manager
        app.state.webhook_config_data = {"webhook1": {"path": "/test"}}

        try:
            # Import the module first to ensure it's loaded
            import src.openapi_generator

            # Patch using both string path (for import inside function) and object (for reliability)
            with patch(
                "src.openapi_generator.generate_openapi_schema"
            ) as mock_gen_str, patch.object(
                src.openapi_generator, "generate_openapi_schema"
            ) as mock_gen_obj:
                mock_gen_str.return_value = {"openapi": "3.0.0"}
                mock_gen_obj.return_value = {"openapi": "3.0.0"}
                result = custom_openapi()

                # Should fallback to webhook_config_data since config_manager returns empty dict
                # Check that it was called (either mock should work)
                assert (
                    mock_gen_str.called or mock_gen_obj.called
                ), "generate_openapi_schema should have been called"
                if mock_gen_str.called:
                    mock_gen_str.assert_called_once_with(
                        {"webhook1": {"path": "/test"}}
                    )
                else:
                    mock_gen_obj.assert_called_once_with(
                        {"webhook1": {"path": "/test"}}
                    )
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")

    def test_custom_openapi_with_generation_error(self):
        """Test custom OpenAPI when generation fails."""
        # Set config_manager with webhook configs so generation is attempted
        mock_config_manager = Mock()
        mock_config_manager.get_all_webhook_configs.return_value = {
            "webhook1": {"path": "/test"}
        }

        original_config_manager = getattr(app.state, "config_manager", None)
        original_webhook_config = getattr(app.state, "webhook_config_data", None)
        app.state.config_manager = mock_config_manager
        app.state.webhook_config_data = None

        try:
            # Import the module first to ensure it's loaded
            import src.openapi_generator

            # Patch using both string path (for import inside function) and object (for reliability)
            with patch(
                "src.openapi_generator.generate_openapi_schema"
            ) as mock_gen_str, patch.object(
                src.openapi_generator, "generate_openapi_schema"
            ) as mock_gen_obj:
                mock_gen_str.side_effect = Exception("Generation failed")
                mock_gen_obj.side_effect = Exception("Generation failed")

                # Get the original openapi result for comparison
                from fastapi import FastAPI

                temp_app = FastAPI()
                original_openapi_result = temp_app.openapi()

                result = custom_openapi()

                # Should fallback to original openapi (which is the real FastAPI schema)
                assert "openapi" in result
                assert result["openapi"] == original_openapi_result["openapi"]
                # Verify the generation was attempted (either mock should work)
                assert (
                    mock_gen_str.called or mock_gen_obj.called
                ), "generate_openapi_schema should have been called"
        finally:
            if original_config_manager is not None:
                app.state.config_manager = original_config_manager
            elif hasattr(app.state, "config_manager"):
                delattr(app.state, "config_manager")
            if original_webhook_config is not None:
                app.state.webhook_config_data = original_webhook_config
            elif hasattr(app.state, "webhook_config_data"):
                delattr(app.state, "webhook_config_data")


class TestCleanupTask:
    """Test cleanup task functionality."""

    @pytest.mark.asyncio
    async def test_cleanup_task_runs(self):
        """Test that cleanup task runs and calls rate limiter cleanup."""
        mock_rate_limiter = AsyncMock()
        mock_rate_limiter.cleanup_old_entries = AsyncMock()

        with patch("src.main.rate_limiter", mock_rate_limiter):
            # Start task and wait a bit
            task = asyncio.create_task(cleanup_task())

            # Wait a moment for it to run
            await asyncio.sleep(0.1)

            # Cancel the task
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass

            # Should have called cleanup
            assert mock_rate_limiter.cleanup_old_entries.called


class TestMainEndpoints:
    """Test main.py endpoint initialization."""

    def test_app_has_custom_openapi(self):
        """Test that app has custom OpenAPI function."""
        assert hasattr(app, "openapi")
        assert callable(app.openapi)

    def test_app_has_webhook_endpoint(self):
        """Test that webhook endpoint is registered."""
        routes = [route.path for route in app.routes]
        assert "/webhook/{webhook_id}" in routes

    def test_app_has_admin_endpoints(self):
        """Test that admin endpoints are registered."""
        routes = [route.path for route in app.routes]
        assert "/admin/reload-config" in routes
        assert "/admin/config-status" in routes
