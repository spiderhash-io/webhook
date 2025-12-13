"""
Integration tests for config_watcher.py.
Tests cover missing coverage areas including error handling and file watching edge cases.
"""
import pytest
import asyncio
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from tempfile import NamedTemporaryFile

from src.config_watcher import ConfigFileWatcher
from src.config_manager import ConfigManager


class TestConfigFileWatcherErrorHandling:
    """Test error handling in config file watcher."""
    
    @pytest.mark.asyncio
    async def test_start_with_file_not_found(self):
        """Test start when config files don't exist."""
        config_manager = ConfigManager(
            webhook_config_file="nonexistent_webhooks.json",
            connection_config_file="nonexistent_connections.json"
        )
        watcher = ConfigFileWatcher(config_manager)
        
        # Should handle gracefully
        watcher.start()
        watcher.stop()
    
    @pytest.mark.asyncio
    async def test_on_modified_with_reload_error(self):
        """Test on_modified when reload fails."""
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f1, \
             NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f2:
            
            f1.write('{"webhook1": {"path": "/test", "module": []}}')
            f2.write('{"conn1": {"type": "redis"}}')
            temp_webhook = f1.name
            temp_conn = f2.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            watcher = ConfigFileWatcher(config_manager)
            config_manager.reload_webhooks = AsyncMock(side_effect=Exception("Reload failed"))
            
            # Start watcher to initialize handler
            watcher.start()
            
            # Simulate file modification event through handler
            from watchdog.events import FileModifiedEvent
            event = FileModifiedEvent(temp_webhook)
            
            # Should handle error gracefully
            watcher.handler.on_modified(event)
            
            # Wait a bit for async operations
            await asyncio.sleep(0.2)
        finally:
            watcher.stop()
            os.unlink(temp_webhook)
            os.unlink(temp_conn)
    
    @pytest.mark.asyncio
    async def test_on_modified_with_connections_reload_error(self):
        """Test on_modified when connections reload fails."""
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f1, \
             NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f2:
            
            f1.write('{"webhook1": {"path": "/test", "module": []}}')
            f2.write('{"conn1": {"type": "redis"}}')
            temp_webhook = f1.name
            temp_conn = f2.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            watcher = ConfigFileWatcher(config_manager)
            config_manager.reload_webhooks = AsyncMock(return_value=Mock(success=True))
            config_manager.reload_connections = AsyncMock(side_effect=Exception("Reload failed"))
            
            # Start watcher to initialize handler
            watcher.start()
            
            # Simulate file modification event through handler
            from watchdog.events import FileModifiedEvent
            event = FileModifiedEvent(temp_conn)
            
            # Should handle error gracefully
            watcher.handler.on_modified(event)
            
            # Wait a bit for async operations
            await asyncio.sleep(0.2)
        finally:
            watcher.stop()
            os.unlink(temp_webhook)
            os.unlink(temp_conn)


class TestConfigFileWatcherThreadHandling:
    """Test thread handling for async operations."""
    
    @pytest.mark.asyncio
    async def test_on_modified_without_running_loop(self):
        """Test on_modified when no event loop is running."""
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f1, \
             NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f2:
            
            f1.write('{"webhook1": {"path": "/test", "module": []}}')
            f2.write('{"conn1": {"type": "redis"}}')
            temp_webhook = f1.name
            temp_conn = f2.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            watcher = ConfigFileWatcher(config_manager, event_loop=None)
            config_manager.reload_webhooks = AsyncMock(return_value=Mock(success=True))
            
            # Start watcher to initialize handler
            watcher.start()
            
            # Simulate file modification event through handler
            from watchdog.events import FileModifiedEvent
            event = FileModifiedEvent(temp_webhook)
            
            # Should create thread for async operation
            watcher.handler.on_modified(event)
            
            # Wait a bit for thread to complete
            await asyncio.sleep(0.2)
        finally:
            watcher.stop()
            os.unlink(temp_webhook)
            os.unlink(temp_conn)


class TestConfigFileWatcherInitialization:
    """Test config file watcher initialization."""
    
    def test_init_with_valid_files(self):
        """Test initialization with valid file paths."""
        with NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f1, \
             NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f2:
            
            f1.write('{}')
            f2.write('{}')
            temp_webhook = f1.name
            temp_conn = f2.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            watcher = ConfigFileWatcher(config_manager)
            
            assert watcher.config_manager == config_manager
            assert watcher.config_manager.webhook_config_file == temp_webhook
            assert watcher.config_manager.connection_config_file == temp_conn
            assert watcher.observer is None  # Not started yet
            
            watcher.stop()
        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)
    
    def test_init_with_relative_paths(self):
        """Test initialization with relative file paths."""
        config_manager = ConfigManager(
            webhook_config_file="webhooks.json",
            connection_config_file="connections.json"
        )
        watcher = ConfigFileWatcher(config_manager)
        
        assert watcher.config_manager.webhook_config_file == "webhooks.json"
        assert watcher.config_manager.connection_config_file == "connections.json"
        
        watcher.stop()

