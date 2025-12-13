"""
Integration tests for analytics_processor.py.
Tests cover missing coverage areas including connection, error handling, and main loop.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from clickhouse_driver import Client

from src.analytics_processor import AnalyticsProcessor, analytics_processing_loop
from src.clickhouse_analytics import ClickHouseAnalytics


class TestAnalyticsProcessorConnection:
    """Test connection establishment and error handling."""
    
    @pytest.mark.asyncio
    async def test_connect_with_valid_config(self):
        """Test connection with valid configuration."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': 'testpass'
        }
        
        processor = AnalyticsProcessor(config)
        
        mock_client = MagicMock()
        mock_client.execute = Mock()
        
        with patch('src.analytics_processor._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('src.analytics_processor.Client', return_value=mock_client), \
             patch('src.analytics_processor.ClickHouseAnalytics') as mock_ch_class:
            
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(return_value=mock_client)
            mock_loop.return_value = mock_loop_instance
            
            mock_analytics = AsyncMock()
            mock_analytics.connect = AsyncMock()
            mock_ch_class.return_value = mock_analytics
            
            await processor.connect()
            
            assert processor.client == mock_client
            mock_analytics.connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connect_with_host_validation_error(self):
        """Test connection with host validation failure."""
        config = {
            'host': 'invalid-host',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        
        with patch('src.analytics_processor._validate_connection_host') as mock_validate:
            mock_validate.side_effect = ValueError("Invalid host")
            
            with pytest.raises(ValueError, match="Host validation failed"):
                await processor.connect()
    
    @pytest.mark.asyncio
    async def test_connect_with_connection_error(self):
        """Test connection error handling."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        
        with patch('src.analytics_processor._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop:
            
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(side_effect=Exception("Connection failed"))
            mock_loop.return_value = mock_loop_instance
            
            with pytest.raises(Exception):
                await processor.connect()


class TestAnalyticsProcessorGetAllWebhookIds:
    """Test get_all_webhook_ids method."""
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_success(self):
        """Test successful retrieval of webhook IDs."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        
        mock_client = MagicMock()
        mock_client.execute = Mock(return_value=[('webhook1',), ('webhook2',), ('webhook3',)])
        processor.client = mock_client
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(return_value=[('webhook1',), ('webhook2',), ('webhook3',)])
            mock_loop.return_value = mock_loop_instance
            
            result = await processor.get_all_webhook_ids()
            
            assert 'webhook1' in result
            assert 'webhook2' in result
            assert 'webhook3' in result
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_with_invalid_ids(self):
        """Test get_all_webhook_ids filters invalid IDs."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        processor.client = MagicMock()  # Set client so method doesn't return early
        
        # Include invalid webhook IDs
        mock_result = [('valid_id',), ('invalid;id',), ('another_valid',)]
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(return_value=mock_result)
            mock_loop.return_value = mock_loop_instance
            
            result = await processor.get_all_webhook_ids()
            
            # Invalid IDs should be filtered out
            assert 'valid_id' in result
            assert 'another_valid' in result
            assert 'invalid;id' not in result
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_with_error(self):
        """Test get_all_webhook_ids error handling."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(side_effect=Exception("Database error"))
            mock_loop.return_value = mock_loop_instance
            
            result = await processor.get_all_webhook_ids()
            
            # Should return empty list on error
            assert result == []


class TestAnalyticsProcessorProcessAndSaveStats:
    """Test process_and_save_stats method."""
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_success(self):
        """Test successful stats processing and saving."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        processor.client = MagicMock()  # Set client so method doesn't return early
        
        mock_analytics = AsyncMock()
        mock_analytics.save_stats = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch.object(processor, 'get_all_webhook_ids', AsyncMock(return_value=['webhook1', 'webhook2'])), \
             patch.object(processor, 'calculate_stats', AsyncMock(side_effect=[
                 {'total': 10, 'minute': 1},
                 {'total': 20, 'minute': 2}
             ])):
            
            await processor.process_and_save_stats()
            
            mock_analytics.save_stats.assert_called_once()
            call_args = mock_analytics.save_stats.call_args[0][0]
            assert 'webhook1' in call_args
            assert 'webhook2' in call_args
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_no_webhooks(self):
        """Test process_and_save_stats with no webhooks."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        
        mock_analytics = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch.object(processor, 'get_all_webhook_ids', AsyncMock(return_value=[])):
            await processor.process_and_save_stats()
            
            # Should not call save_stats when no webhooks
            mock_analytics.save_stats.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_with_error(self):
        """Test process_and_save_stats error handling."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        
        mock_analytics = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch.object(processor, 'get_all_webhook_ids', AsyncMock(side_effect=Exception("Error"))):
            # Should not raise, should handle gracefully
            await processor.process_and_save_stats()


class TestAnalyticsProcessorDisconnect:
    """Test disconnect method."""
    
    @pytest.mark.asyncio
    async def test_disconnect_with_client(self):
        """Test disconnect with active client."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        
        mock_client = MagicMock()
        mock_client.disconnect = Mock()
        processor.client = mock_client
        
        mock_analytics = AsyncMock()
        mock_analytics.disconnect = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock()
            mock_loop.return_value = mock_loop_instance
            
            await processor.disconnect()
            
            mock_analytics.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_without_client(self):
        """Test disconnect without client."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        
        processor.client = None
        
        mock_analytics = AsyncMock()
        mock_analytics.disconnect = AsyncMock()
        processor.analytics = mock_analytics
        
        await processor.disconnect()
        
        # Should still disconnect analytics
        mock_analytics.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_with_error(self):
        """Test disconnect error handling."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        processor = AnalyticsProcessor(config)
        
        mock_client = MagicMock()
        processor.client = mock_client
        
        mock_analytics = AsyncMock()
        mock_analytics.disconnect = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(side_effect=Exception("Disconnect error"))
            mock_loop.return_value = mock_loop_instance
            
            # Should not raise, should handle gracefully
            await processor.disconnect()


class TestAnalyticsProcessingLoop:
    """Test main analytics processing loop."""
    
    @pytest.mark.asyncio
    async def test_analytics_processing_loop_no_clickhouse_config(self):
        """Test processing loop when no ClickHouse config exists."""
        with patch('src.analytics_processor.load_env_vars', return_value={}):
            # Should return early without error
            await analytics_processing_loop()
    
    @pytest.mark.asyncio
    async def test_analytics_processing_loop_with_config(self):
        """Test processing loop with ClickHouse config."""
        config = {
            'clickhouse1': {
                'type': 'clickhouse',
                'host': 'localhost',
                'port': 9000,
                'database': 'test',
                'user': 'default',
                'password': ''
            }
        }
        
        with patch('src.analytics_processor.load_env_vars', return_value=config), \
             patch('src.analytics_processor.AnalyticsProcessor') as mock_processor_class:
            
            mock_processor = AsyncMock()
            mock_processor.connect = AsyncMock()
            mock_processor.process_and_save_stats = AsyncMock()
            mock_processor.disconnect = AsyncMock()
            mock_processor_class.return_value = mock_processor
            
            # Start loop and cancel quickly
            task = asyncio.create_task(analytics_processing_loop())
            await asyncio.sleep(0.1)
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            mock_processor.connect.assert_called_once()
            mock_processor.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analytics_processing_loop_keyboard_interrupt(self):
        """Test processing loop handles KeyboardInterrupt."""
        config = {
            'clickhouse1': {
                'type': 'clickhouse',
                'host': 'localhost',
                'port': 9000,
                'database': 'test',
                'user': 'default',
                'password': ''
            }
        }
        
        with patch('src.analytics_processor.load_env_vars', return_value=config), \
             patch('src.analytics_processor.AnalyticsProcessor') as mock_processor_class:
            
            mock_processor = AsyncMock()
            mock_processor.connect = AsyncMock()
            mock_processor.process_and_save_stats = AsyncMock(side_effect=KeyboardInterrupt())
            mock_processor.disconnect = AsyncMock()
            mock_processor_class.return_value = mock_processor
            
            await analytics_processing_loop()
            
            mock_processor.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analytics_processing_loop_with_fatal_error(self):
        """Test processing loop handles fatal errors."""
        config = {
            'clickhouse1': {
                'type': 'clickhouse',
                'host': 'localhost',
                'port': 9000,
                'database': 'test',
                'user': 'default',
                'password': ''
            }
        }
        
        with patch('src.analytics_processor.load_env_vars', return_value=config), \
             patch('src.analytics_processor.AnalyticsProcessor') as mock_processor_class:
            
            mock_processor = AsyncMock()
            mock_processor.connect = AsyncMock()
            mock_processor.process_and_save_stats = AsyncMock(side_effect=Exception("Fatal error"))
            mock_processor.disconnect = AsyncMock()
            mock_processor_class.return_value = mock_processor
            
            # Should handle error gracefully
            await analytics_processing_loop()
            
            mock_processor.disconnect.assert_called_once()

