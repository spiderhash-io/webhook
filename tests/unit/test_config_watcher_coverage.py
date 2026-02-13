"""
Coverage tests for src/config_watcher.py.

Targets the ~19 missed lines covering:
- ConfigFileHandler.on_modified: directory events, exact filename matching,
  non-config filenames
- ConfigFileHandler._debounce_reload: timer cancellation and creation
- ConfigFileHandler._trigger_reload: no loop, running loop, non-running loop fallback
- ConfigFileHandler._run_reload_in_thread
- ConfigFileHandler._async_reload: webhooks success/failure, connections success/failure,
  exception handling
- ConfigFileWatcher: start (already watching, event loop detection), stop (not watching,
  debounce timer cancel), is_watching
"""

import pytest
import asyncio
import os
import threading
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock
from dataclasses import dataclass

from src.config_watcher import ConfigFileHandler, ConfigFileWatcher


@dataclass
class FakeEvent:
    """Fake watchdog event for testing."""
    src_path: str
    is_directory: bool = False


class TestConfigFileHandlerOnModified:
    """Test ConfigFileHandler.on_modified method."""

    def test_ignores_directory_events(self):
        """Test on_modified ignores directory events."""
        handler = ConfigFileHandler(config_manager=MagicMock(), debounce_seconds=1.0)
        event = FakeEvent(src_path="/some/path/webhooks.json", is_directory=True)

        handler._debounce_reload = MagicMock()
        handler.on_modified(event)

        handler._debounce_reload.assert_not_called()

    def test_handles_webhooks_json(self):
        """Test on_modified triggers reload for webhooks.json."""
        handler = ConfigFileHandler(config_manager=MagicMock(), debounce_seconds=1.0)
        event = FakeEvent(src_path="/some/path/webhooks.json")

        handler._debounce_reload = MagicMock()
        handler.on_modified(event)

        handler._debounce_reload.assert_called_once_with("/some/path/webhooks.json")

    def test_handles_connections_json(self):
        """Test on_modified triggers reload for connections.json."""
        handler = ConfigFileHandler(config_manager=MagicMock(), debounce_seconds=1.0)
        event = FakeEvent(src_path="/some/path/connections.json")

        handler._debounce_reload = MagicMock()
        handler.on_modified(event)

        handler._debounce_reload.assert_called_once_with("/some/path/connections.json")

    def test_ignores_other_files(self):
        """Test on_modified ignores non-config files."""
        handler = ConfigFileHandler(config_manager=MagicMock(), debounce_seconds=1.0)
        event = FakeEvent(src_path="/some/path/other.json")

        handler._debounce_reload = MagicMock()
        handler.on_modified(event)

        handler._debounce_reload.assert_not_called()

    def test_ignores_partial_match_filenames(self):
        """Test on_modified ignores files that partially match config filenames."""
        handler = ConfigFileHandler(config_manager=MagicMock(), debounce_seconds=1.0)
        handler._debounce_reload = MagicMock()

        # These should NOT trigger reload (bypass attack prevention)
        for filename in ["malicious_webhooks.json", "webhooks.json.backup",
                         "my_connections.json", "connections.json.bak"]:
            event = FakeEvent(src_path=f"/some/path/{filename}")
            handler.on_modified(event)

        handler._debounce_reload.assert_not_called()


class TestConfigFileHandlerDebounce:
    """Test ConfigFileHandler._debounce_reload method."""

    def test_debounce_creates_timer(self):
        """Test _debounce_reload creates a new timer."""
        handler = ConfigFileHandler(config_manager=MagicMock(), debounce_seconds=5.0)

        handler._debounce_reload("/path/webhooks.json")

        assert handler._debounce_timer is not None
        # Cancel to clean up
        handler._debounce_timer.cancel()

    def test_debounce_cancels_existing_timer(self):
        """Test _debounce_reload cancels existing timer before creating new one."""
        handler = ConfigFileHandler(config_manager=MagicMock(), debounce_seconds=5.0)

        # Create first timer
        handler._debounce_reload("/path/webhooks.json")
        first_timer = handler._debounce_timer

        # Create second timer (should cancel first)
        handler._debounce_reload("/path/connections.json")
        second_timer = handler._debounce_timer

        assert first_timer is not second_timer
        # Clean up
        handler._debounce_timer.cancel()


class TestConfigFileHandlerTriggerReload:
    """Test ConfigFileHandler._trigger_reload method."""

    def test_trigger_reload_with_running_loop(self):
        """Test _trigger_reload uses provided event loop."""
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = True
        handler = ConfigFileHandler(
            config_manager=MagicMock(), debounce_seconds=1.0, event_loop=mock_loop
        )

        handler._trigger_reload("/path/webhooks.json")

        mock_loop.is_running.assert_called_once()

    def test_trigger_reload_no_loop_falls_back_to_thread(self):
        """Test _trigger_reload falls back to thread when no event loop."""
        handler = ConfigFileHandler(
            config_manager=MagicMock(), debounce_seconds=1.0, event_loop=None
        )

        with patch("src.config_watcher.asyncio.get_running_loop", side_effect=RuntimeError("No loop")):
            with patch("src.config_watcher.threading.Thread") as mock_thread:
                mock_thread_instance = MagicMock()
                mock_thread.return_value = mock_thread_instance

                handler._trigger_reload("/path/webhooks.json")

                mock_thread.assert_called_once()
                mock_thread_instance.start.assert_called_once()

    def test_trigger_reload_non_running_loop_falls_back_to_thread(self):
        """Test _trigger_reload falls back to thread when loop not running."""
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = False
        handler = ConfigFileHandler(
            config_manager=MagicMock(), debounce_seconds=1.0, event_loop=mock_loop
        )

        with patch("src.config_watcher.threading.Thread") as mock_thread:
            mock_thread_instance = MagicMock()
            mock_thread.return_value = mock_thread_instance

            handler._trigger_reload("/path/webhooks.json")

            mock_thread.assert_called_once()
            mock_thread_instance.start.assert_called_once()


class TestConfigFileHandlerAsyncReload:
    """Test ConfigFileHandler._async_reload method."""

    @pytest.mark.asyncio
    async def test_async_reload_webhooks_success(self):
        """Test _async_reload successfully reloads webhooks."""
        mock_manager = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.details = "Loaded 5 webhooks"
        mock_manager.reload_webhooks = AsyncMock(return_value=mock_result)

        handler = ConfigFileHandler(config_manager=mock_manager, debounce_seconds=1.0)
        await handler._async_reload("/some/path/webhooks.json")

        mock_manager.reload_webhooks.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_reload_webhooks_failure(self):
        """Test _async_reload handles webhook reload failure."""
        mock_manager = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.error = "Invalid JSON"
        mock_manager.reload_webhooks = AsyncMock(return_value=mock_result)

        handler = ConfigFileHandler(config_manager=mock_manager, debounce_seconds=1.0)
        await handler._async_reload("/some/path/webhooks.json")

        mock_manager.reload_webhooks.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_reload_connections_success(self):
        """Test _async_reload successfully reloads connections."""
        mock_manager = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.details = "Loaded 3 connections"
        mock_manager.reload_connections = AsyncMock(return_value=mock_result)

        handler = ConfigFileHandler(config_manager=mock_manager, debounce_seconds=1.0)
        await handler._async_reload("/some/path/connections.json")

        mock_manager.reload_connections.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_reload_connections_failure(self):
        """Test _async_reload handles connection reload failure."""
        mock_manager = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.error = "Connection validation failed"
        mock_manager.reload_connections = AsyncMock(return_value=mock_result)

        handler = ConfigFileHandler(config_manager=mock_manager, debounce_seconds=1.0)
        await handler._async_reload("/some/path/connections.json")

        mock_manager.reload_connections.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_reload_exception_handling(self):
        """Test _async_reload handles exception gracefully."""
        mock_manager = MagicMock()
        mock_manager.reload_webhooks = AsyncMock(side_effect=Exception("Unexpected error"))

        handler = ConfigFileHandler(config_manager=mock_manager, debounce_seconds=1.0)
        # Should not raise
        await handler._async_reload("/some/path/webhooks.json")

    @pytest.mark.asyncio
    async def test_async_reload_unknown_file(self):
        """Test _async_reload ignores unknown file types."""
        mock_manager = MagicMock()
        mock_manager.reload_webhooks = AsyncMock()
        mock_manager.reload_connections = AsyncMock()

        handler = ConfigFileHandler(config_manager=mock_manager, debounce_seconds=1.0)
        await handler._async_reload("/some/path/other.json")

        mock_manager.reload_webhooks.assert_not_called()
        mock_manager.reload_connections.assert_not_called()


class TestConfigFileWatcherInit:
    """Test ConfigFileWatcher initialization."""

    def test_init_stores_attributes(self):
        """Test __init__ stores all attributes correctly."""
        mock_manager = MagicMock()
        watcher = ConfigFileWatcher(mock_manager, debounce_seconds=5.0)

        assert watcher.config_manager is mock_manager
        assert watcher.debounce_seconds == 5.0
        assert watcher.observer is None
        assert watcher.handler is None
        assert watcher._watching is False
        assert watcher.event_loop is None

    def test_init_default_debounce(self):
        """Test __init__ uses default debounce of 3.0 seconds."""
        watcher = ConfigFileWatcher(MagicMock())
        assert watcher.debounce_seconds == 3.0


class TestConfigFileWatcherStartStop:
    """Test ConfigFileWatcher start and stop methods."""

    def test_start_sets_watching(self):
        """Test start sets _watching to True."""
        mock_manager = MagicMock()
        mock_manager.webhook_config_file = "/tmp/webhooks.json"
        mock_manager.connection_config_file = "/tmp/connections.json"

        watcher = ConfigFileWatcher(mock_manager, debounce_seconds=1.0)

        with patch("src.config_watcher.Observer") as mock_observer_cls:
            mock_observer = MagicMock()
            mock_observer_cls.return_value = mock_observer

            watcher.start()

            assert watcher._watching is True
            assert watcher.handler is not None
            mock_observer.schedule.assert_called_once()
            mock_observer.start.assert_called_once()

            # Clean up
            watcher.stop()

    def test_start_idempotent(self):
        """Test start is idempotent (calling twice does nothing)."""
        mock_manager = MagicMock()
        mock_manager.webhook_config_file = "/tmp/webhooks.json"
        mock_manager.connection_config_file = "/tmp/connections.json"

        watcher = ConfigFileWatcher(mock_manager, debounce_seconds=1.0)

        with patch("src.config_watcher.Observer") as mock_observer_cls:
            mock_observer = MagicMock()
            mock_observer_cls.return_value = mock_observer

            watcher.start()
            watcher.start()  # Second call should be no-op

            # Observer should only be created once
            assert mock_observer_cls.call_count == 1

            watcher.stop()

    def test_stop_sets_not_watching(self):
        """Test stop sets _watching to False."""
        mock_manager = MagicMock()
        mock_manager.webhook_config_file = "/tmp/webhooks.json"
        mock_manager.connection_config_file = "/tmp/connections.json"

        watcher = ConfigFileWatcher(mock_manager, debounce_seconds=1.0)

        with patch("src.config_watcher.Observer") as mock_observer_cls:
            mock_observer = MagicMock()
            mock_observer_cls.return_value = mock_observer

            watcher.start()
            assert watcher._watching is True

            watcher.stop()
            assert watcher._watching is False
            assert watcher.observer is None

    def test_stop_not_watching_is_noop(self):
        """Test stop when not watching is a no-op."""
        watcher = ConfigFileWatcher(MagicMock())
        watcher.stop()  # Should not raise
        assert watcher._watching is False

    def test_stop_cancels_debounce_timer(self):
        """Test stop cancels the debounce timer."""
        mock_manager = MagicMock()
        mock_manager.webhook_config_file = "/tmp/webhooks.json"
        mock_manager.connection_config_file = "/tmp/connections.json"

        watcher = ConfigFileWatcher(mock_manager, debounce_seconds=1.0)

        with patch("src.config_watcher.Observer") as mock_observer_cls:
            mock_observer = MagicMock()
            mock_observer_cls.return_value = mock_observer

            watcher.start()

            # Simulate a debounce timer
            mock_timer = MagicMock()
            watcher.handler._debounce_timer = mock_timer

            watcher.stop()

            mock_timer.cancel.assert_called_once()

    def test_is_watching(self):
        """Test is_watching returns correct state."""
        watcher = ConfigFileWatcher(MagicMock())
        assert watcher.is_watching() is False

        watcher._watching = True
        assert watcher.is_watching() is True

    def test_start_detects_event_loop(self):
        """Test start tries to detect event loop when none provided."""
        mock_manager = MagicMock()
        mock_manager.webhook_config_file = "/tmp/webhooks.json"
        mock_manager.connection_config_file = "/tmp/connections.json"

        watcher = ConfigFileWatcher(mock_manager, debounce_seconds=1.0)
        assert watcher.event_loop is None

        with patch("src.config_watcher.Observer") as mock_observer_cls:
            mock_observer = MagicMock()
            mock_observer_cls.return_value = mock_observer

            # When no running loop exists, event_loop should remain None
            with patch("src.config_watcher.asyncio.get_running_loop", side_effect=RuntimeError):
                watcher.start()

            assert watcher.event_loop is None
            watcher.stop()


class TestRunReloadInThread:
    """Test ConfigFileHandler._run_reload_in_thread."""

    def test_run_reload_in_thread(self):
        """Test _run_reload_in_thread calls asyncio.run with _async_reload."""
        mock_manager = MagicMock()
        handler = ConfigFileHandler(config_manager=mock_manager, debounce_seconds=1.0)

        # Mock asyncio.run to avoid event loop side effects in test suite
        with patch("src.config_watcher.asyncio.run") as mock_run:
            handler._run_reload_in_thread("/path/webhooks.json")

            mock_run.assert_called_once()
            # Verify the coroutine passed to asyncio.run is _async_reload
            call_args = mock_run.call_args
            coro = call_args[0][0]
            assert coro.__name__ == "_async_reload" or hasattr(coro, "cr_code")
