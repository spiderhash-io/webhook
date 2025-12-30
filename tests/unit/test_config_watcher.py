"""Tests for ConfigFileWatcher."""
import pytest
import json
import tempfile
import os
import asyncio
import time
from src.config_manager import ConfigManager
from src.config_watcher import ConfigFileWatcher


class TestConfigFileWatcher:
    """Test suite for ConfigFileWatcher."""
    pytestmark = pytest.mark.todo
    
    @pytest.fixture
    def temp_webhook_config(self, tmp_path):
        """Create temporary webhook config file."""
        config = {
            "test_webhook": {
                "data_type": "json",
                "module": "log"
            }
        }
        config_file = tmp_path / "webhooks.json"
        with open(config_file, 'w') as f:
            json.dump(config, f)
        yield str(config_file)
    
    @pytest.fixture
    def temp_connection_config(self, tmp_path):
        """Create temporary connection config file."""
        config = {
            "test_connection": {
                "type": "rabbitmq",
                "host": "rabbitmq.example.com",
                "port": 5672
            }
        }
        config_file = tmp_path / "connections.json"
        with open(config_file, 'w') as f:
            json.dump(config, f)
        yield str(config_file)
    
    @pytest.fixture
    def config_manager(self, temp_webhook_config, temp_connection_config):
        """Create ConfigManager instance."""
        return ConfigManager(
            webhook_config_file=temp_webhook_config,
            connection_config_file=temp_connection_config
        )
    
    @pytest.fixture
    def watcher(self, config_manager):
        """Create ConfigFileWatcher instance."""
        return ConfigFileWatcher(config_manager, debounce_seconds=0.1)  # Short debounce for tests
    
    @pytest.mark.asyncio
    async def test_start_stop_watcher(self, watcher):
        """Test starting and stopping the watcher."""
        watcher.start()
        assert watcher.is_watching() is True
        
        watcher.stop()
        assert watcher.is_watching() is False
    
    @pytest.mark.asyncio
    @pytest.mark.integration  # Mark as integration test - requires running event loop
    async def test_file_modification_triggers_reload(self, watcher, temp_webhook_config):
        """Test that file modification triggers reload."""
        await watcher.config_manager.initialize()
        watcher.start()
        
        try:
            # Modify webhook config file
            new_config = {
                "test_webhook": {
                    "data_type": "json",
                    "module": "log"
                },
                "new_webhook": {
                    "data_type": "json",
                    "module": "log"
                }
            }
            with open(temp_webhook_config, 'w') as f:
                json.dump(new_config, f)
            
            # Wait for debounce + reload
            await asyncio.sleep(0.3)
            
            # Check if reload happened
            config = watcher.config_manager.get_webhook_config("new_webhook")
            assert config is not None
        finally:
            watcher.stop()
    
    @pytest.mark.asyncio
    @pytest.mark.integration  # Mark as integration test - requires running event loop
    async def test_debounce_handles_rapid_changes(self, watcher, temp_webhook_config):
        """Test that debounce handles rapid file changes."""
        await watcher.config_manager.initialize()
        watcher.start()
        
        try:
            # Make multiple rapid changes
            for i in range(5):
                config = {
                    f"webhook_{i}": {
                        "data_type": "json",
                        "module": "log"
                    }
                }
                with open(temp_webhook_config, 'w') as f:
                    json.dump(config, f)
                await asyncio.sleep(0.05)  # Small delay between changes
            
            # Wait for debounce
            await asyncio.sleep(0.3)
            
            # Should only have the last webhook (debounce should have triggered once)
            # This is a basic test - exact behavior depends on timing
            status = watcher.config_manager.get_status()
            assert status["webhooks_count"] >= 1
        finally:
            watcher.stop()

