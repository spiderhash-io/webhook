"""
Integration tests for main.py startup, shutdown, and initialization logic.
Tests cover missing coverage areas in main.py.
"""
import pytest
import asyncio
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from src.main import app, startup_event, shutdown_event, cleanup_task, custom_openapi
from src.config_manager import ConfigManager
from src.clickhouse_analytics import ClickHouseAnalytics


class TestMainStartupShutdown:
    """Test startup and shutdown event handlers."""
    
    @pytest.mark.asyncio
    async def test_startup_event_with_config_manager_success(self):
        """Test startup event with successful ConfigManager initialization."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details="Initialized")
            mock_cm._connection_config = {}
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            mock_cm.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_startup_event_with_config_manager_failure(self):
        """Test startup event when ConfigManager initialization fails."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.connection_config', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.inject_connection_details', AsyncMock(return_value={})), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.side_effect = Exception("Init failed")
            mock_cm._connection_config = {}  # Make it a dict to avoid iteration issues
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            # Should handle error gracefully
            mock_cm.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_startup_event_with_clickhouse_config(self):
        """Test startup event with ClickHouse configuration."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ClickHouseAnalytics') as mock_ch_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details="Initialized")
            mock_cm._connection_config = {
                'clickhouse1': {'type': 'clickhouse', 'host': 'localhost'}
            }
            mock_cm_class.return_value = mock_cm
            
            mock_ch = AsyncMock()
            mock_ch_class.return_value = mock_ch
            
            await startup_event()
            
            # ClickHouse should be initialized
            mock_ch_class.assert_called_once()
            mock_ch.connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_startup_event_without_clickhouse_config(self):
        """Test startup event without ClickHouse configuration."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details="Initialized")
            mock_cm._connection_config = {}
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            # Should not fail even without ClickHouse
    
    @pytest.mark.asyncio
    async def test_shutdown_event_with_all_components(self):
        """Test shutdown event with all components present."""
        mock_watcher = Mock()
        mock_watcher.stop = Mock()
        
        mock_manager = AsyncMock()
        mock_manager.pool_registry = AsyncMock()
        mock_manager.pool_registry.close_all_pools = AsyncMock()
        
        mock_clickhouse = AsyncMock()
        mock_clickhouse.disconnect = AsyncMock()
        
        mock_stats = AsyncMock()
        mock_stats.close = AsyncMock()
        
        with patch('src.main.config_watcher', mock_watcher), \
             patch('src.main.config_manager', mock_manager), \
             patch('src.main.clickhouse_logger', mock_clickhouse), \
             patch('src.main.stats', mock_stats):
            
            await shutdown_event()
            
            mock_watcher.stop.assert_called_once()
            mock_manager.pool_registry.close_all_pools.assert_called_once()
            mock_clickhouse.disconnect.assert_called_once()
            mock_stats.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_shutdown_event_with_errors(self):
        """Test shutdown event handles errors gracefully."""
        mock_watcher = Mock()
        mock_watcher.stop.side_effect = Exception("Stop failed")
        
        mock_manager = AsyncMock()
        mock_manager.pool_registry = AsyncMock()
        mock_manager.pool_registry.close_all_pools.side_effect = Exception("Close failed")
        
        mock_clickhouse = AsyncMock()
        mock_clickhouse.disconnect.side_effect = Exception("Disconnect failed")
        
        mock_stats = AsyncMock()
        mock_stats.close.side_effect = Exception("Stats close failed")
        
        with patch('src.main.config_watcher', mock_watcher), \
             patch('src.main.config_manager', mock_manager), \
             patch('src.main.clickhouse_logger', mock_clickhouse), \
             patch('src.main.stats', mock_stats):
            
            # Should not raise exceptions
            await shutdown_event()
            
            # All should be called despite errors
            mock_watcher.stop.assert_called_once()
            mock_manager.pool_registry.close_all_pools.assert_called_once()
            mock_clickhouse.disconnect.assert_called_once()
            mock_stats.close.assert_called_once()


class TestCustomOpenAPI:
    """Test custom OpenAPI schema generation."""
    
    def test_custom_openapi_with_config_manager(self):
        """Test custom OpenAPI with ConfigManager."""
        mock_config_manager = Mock()
        mock_config_manager._webhook_config = {'webhook1': {'path': '/test'}}
        
        with patch('src.main.config_manager', mock_config_manager), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.openapi_generator.generate_openapi_schema') as mock_gen:
            
            mock_gen.return_value = {'openapi': '3.0.0'}
            result = custom_openapi()
            
            mock_gen.assert_called_once_with({'webhook1': {'path': '/test'}})
            assert result == {'openapi': '3.0.0'}
    
    def test_custom_openapi_without_config_manager(self):
        """Test custom OpenAPI without ConfigManager."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {'webhook1': {'path': '/test'}}), \
             patch('src.openapi_generator.generate_openapi_schema') as mock_gen:
            
            mock_gen.return_value = {'openapi': '3.0.0'}
            result = custom_openapi()
            
            mock_gen.assert_called_once_with({'webhook1': {'path': '/test'}})
    
    def test_custom_openapi_with_attribute_error(self):
        """Test custom OpenAPI when _webhook_config access fails."""
        mock_config_manager = Mock()
        mock_config_manager._webhook_config = None
        del mock_config_manager._webhook_config  # Make it raise AttributeError
        
        with patch('src.main.config_manager', mock_config_manager), \
             patch('src.main.webhook_config_data', {'webhook1': {'path': '/test'}}), \
             patch('src.openapi_generator.generate_openapi_schema') as mock_gen:
            
            mock_gen.return_value = {'openapi': '3.0.0'}
            result = custom_openapi()
            
            # Should fallback to webhook_config_data
            mock_gen.assert_called_once_with({'webhook1': {'path': '/test'}})
    
    def test_custom_openapi_with_generation_error(self):
        """Test custom OpenAPI when generation fails."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.openapi_generator.generate_openapi_schema') as mock_gen, \
             patch('src.main.original_openapi') as mock_orig:
            
            mock_gen.side_effect = Exception("Generation failed")
            mock_orig.return_value = {'openapi': '3.0.0', 'fallback': True}
            
            result = custom_openapi()
            
            # Should fallback to original
            assert result == {'openapi': '3.0.0', 'fallback': True}


class TestCleanupTask:
    """Test cleanup task functionality."""
    
    @pytest.mark.asyncio
    async def test_cleanup_task_runs(self):
        """Test that cleanup task runs and calls rate limiter cleanup."""
        mock_rate_limiter = AsyncMock()
        mock_rate_limiter.cleanup_old_entries = AsyncMock()
        
        with patch('src.main.rate_limiter', mock_rate_limiter):
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
        assert hasattr(app, 'openapi')
        assert callable(app.openapi)
    
    def test_app_has_webhook_endpoint(self):
        """Test that webhook endpoint is registered."""
        routes = [route.path for route in app.routes]
        assert '/webhook/{webhook_id}' in routes
    
    def test_app_has_admin_endpoints(self):
        """Test that admin endpoints are registered."""
        routes = [route.path for route in app.routes]
        assert '/admin/reload-config' in routes
        assert '/admin/config-status' in routes

