"""
Comprehensive unit tests to fill coverage gaps in analytics_processor.py.
Target: 100% coverage for AnalyticsProcessor class.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from src.analytics_processor import AnalyticsProcessor, analytics_processing_loop
from src.clickhouse_analytics import ClickHouseAnalytics


class TestAnalyticsProcessorInit:
    """Test AnalyticsProcessor.__init__() with various configs."""
    
    def test_init_with_full_config(self):
        """Test initialization with full configuration."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }
        processor = AnalyticsProcessor(config)
        assert processor.clickhouse_config == config
        assert processor.client is None
        assert processor.analytics is None
    
    def test_init_with_minimal_config(self):
        """Test initialization with minimal configuration."""
        config = {
            'host': 'localhost'
        }
        processor = AnalyticsProcessor(config)
        assert processor.clickhouse_config == config
    
    def test_init_with_empty_config(self):
        """Test initialization with empty configuration."""
        config = {}
        processor = AnalyticsProcessor(config)
        assert processor.clickhouse_config == config


class TestAnalyticsProcessorConnect:
    """Test AnalyticsProcessor.connect() - connection success/failure."""
    
    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful connection to ClickHouse."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_client.execute = Mock(return_value=None)  # Mock execute to return None
        
        mock_analytics = AsyncMock()
        mock_analytics.connect = AsyncMock()
        
        with patch('src.analytics_processor._validate_connection_host', return_value='localhost'), \
             patch('src.clickhouse_analytics._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('clickhouse_driver.Client', return_value=mock_client):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    result = func()
                    # If result is a Client instance, return mock_client instead
                    if hasattr(result, 'execute'):
                        return mock_client
                    return result
                return mock_client
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            with patch('src.analytics_processor.ClickHouseAnalytics', return_value=mock_analytics):
                await processor.connect()
            
            assert processor.client is not None
            assert processor.analytics is not None
            mock_analytics.connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connect_with_empty_password(self):
        """Test connection with empty password."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': ''
        }
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_client.execute = Mock(return_value=None)  # Mock execute to return None
        
        mock_analytics = AsyncMock()
        mock_analytics.connect = AsyncMock()
        
        with patch('src.analytics_processor._validate_connection_host', return_value='localhost'), \
             patch('src.clickhouse_analytics._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('clickhouse_driver.Client', return_value=mock_client):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    result = func()
                    # If result is a Client instance, return mock_client instead
                    if hasattr(result, 'execute'):
                        return mock_client
                    return result
                return mock_client
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            with patch('src.clickhouse_analytics.ClickHouseAnalytics', return_value=mock_analytics):
                await processor.connect()
            
            assert processor.client is not None
    
    @pytest.mark.asyncio
    async def test_connect_with_none_password(self):
        """Test connection with None password."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': None
        }
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_client.execute = Mock(return_value=None)  # Mock execute to return None
        
        mock_analytics = AsyncMock()
        mock_analytics.connect = AsyncMock()
        
        with patch('src.analytics_processor._validate_connection_host', return_value='localhost'), \
             patch('src.clickhouse_analytics._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('clickhouse_driver.Client', return_value=mock_client):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    result = func()
                    # If result is a Client instance, return mock_client instead
                    if hasattr(result, 'execute'):
                        return mock_client
                    return result
                return mock_client
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            with patch('src.clickhouse_analytics.ClickHouseAnalytics', return_value=mock_analytics):
                await processor.connect()
            
            assert processor.client is not None
    
    @pytest.mark.asyncio
    async def test_connect_host_validation_failure(self):
        """Test connection failure due to host validation."""
        config = {
            'host': '192.168.1.1',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }
        processor = AnalyticsProcessor(config)
        
        with patch('src.analytics_processor._validate_connection_host', side_effect=ValueError("Invalid host")):
            with pytest.raises(ValueError, match="Host validation failed"):
                await processor.connect()
    
    @pytest.mark.asyncio
    async def test_connect_client_creation_failure(self):
        """Test connection failure during client creation."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }
        processor = AnalyticsProcessor(config)
        
        with patch('src.config._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop:
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=Exception("Connection failed"))
            
            with pytest.raises(Exception):
                await processor.connect()
    
    @pytest.mark.asyncio
    async def test_connect_analytics_connect_failure(self):
        """Test connection failure during analytics.connect()."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_client.execute = Mock()
        
        mock_analytics = AsyncMock()
        mock_analytics.connect = AsyncMock(side_effect=Exception("Analytics connect failed"))
        
        with patch('src.config._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop:
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return mock_client
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            with patch('src.clickhouse_analytics.ClickHouseAnalytics', return_value=mock_analytics):
                with pytest.raises(Exception):
                    await processor.connect()


class TestAnalyticsProcessorDisconnect:
    """Test AnalyticsProcessor.disconnect() - all paths."""
    
    @pytest.mark.asyncio
    async def test_disconnect_with_client_and_analytics(self):
        """Test disconnect with both client and analytics."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_client.disconnect = Mock()
        processor.client = mock_client
        
        mock_analytics = AsyncMock()
        mock_analytics.disconnect = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await processor.disconnect()
            
            mock_client.disconnect.assert_called_once()
            mock_analytics.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_with_client_only(self):
        """Test disconnect with client only."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_client.disconnect = Mock()
        processor.client = mock_client
        processor.analytics = None
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await processor.disconnect()
            
            mock_client.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_with_analytics_only(self):
        """Test disconnect with analytics only."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        processor.client = None
        
        mock_analytics = AsyncMock()
        mock_analytics.disconnect = AsyncMock()
        processor.analytics = mock_analytics
        
        await processor.disconnect()
        
        mock_analytics.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_with_none(self):
        """Test disconnect with no client or analytics."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        processor.client = None
        processor.analytics = None
        
        # Should not raise exception
        await processor.disconnect()
    
    @pytest.mark.asyncio
    async def test_disconnect_client_exception(self):
        """Test disconnect when client.disconnect() raises exception."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_client.disconnect = Mock(side_effect=Exception("Disconnect failed"))
        processor.client = mock_client
        processor.analytics = None
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            # Should not raise exception
            await processor.disconnect()


class TestAnalyticsProcessorGetAllWebhookIds:
    """Test AnalyticsProcessor.get_all_webhook_ids() - with/without data."""
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_with_data(self):
        """Test get_all_webhook_ids with data."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_client.execute = Mock(return_value=[('webhook1',), ('webhook2',), ('webhook3',)])
        processor.client = mock_client
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return [('webhook1',), ('webhook2',), ('webhook3',)]
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            result = await processor.get_all_webhook_ids()
            
            assert len(result) == 3
            assert 'webhook1' in result
            assert 'webhook2' in result
            assert 'webhook3' in result
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_without_data(self):
        """Test get_all_webhook_ids without data."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return []
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            result = await processor.get_all_webhook_ids()
            
            assert result == []
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_with_none_client(self):
        """Test get_all_webhook_ids with None client."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        processor.client = None
        
        result = await processor.get_all_webhook_ids()
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_with_invalid_ids(self):
        """Test get_all_webhook_ids with invalid webhook IDs from database."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        # Include invalid IDs that will be filtered out
        invalid_ids = [
            ('webhook1',),  # Valid
            ('webhook;id',),  # Invalid - contains semicolon
            ('webhook2',),  # Valid
            ('webhook\nid',),  # Invalid - contains newline
        ]
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    result = func()
                    # If the function returns a Mock, return the actual data
                    if isinstance(result, Mock):
                        return invalid_ids
                    return result
                return invalid_ids
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            result = await processor.get_all_webhook_ids()
            
            # Only valid IDs should be returned
            assert 'webhook1' in result
            assert 'webhook2' in result
            assert len(result) == 2
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_exception(self):
        """Test get_all_webhook_ids with exception."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=Exception("Query failed"))
            
            with patch('builtins.print'):
                result = await processor.get_all_webhook_ids()
                
                assert result == []


class TestAnalyticsProcessorCalculateStats:
    """Test AnalyticsProcessor.calculate_stats() - all calculation paths."""
    
    @pytest.mark.asyncio
    async def test_calculate_stats_with_data(self):
        """Test calculate_stats with data."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        mock_result = [
            (1000, 10, 50, 150, 300, 500, 800, 900, 950)  # total, minute, 5min, 15min, 30min, hour, day, week, month
        ]
        processor.client = mock_client
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    result = func()
                    # If it's the execute call, return the mock_result
                    if isinstance(result, Mock):
                        return mock_result
                    return result
                return mock_result
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            result = await processor.calculate_stats('test_webhook')
            
            assert result['total'] == 1000
            assert result['minute'] == 10
            assert result['5_minutes'] == 50
            assert result['15_minutes'] == 150
            assert result['30_minutes'] == 300
            assert result['hour'] == 500
            assert result['day'] == 800
            assert result['week'] == 900
            assert result['month'] == 950
    
    @pytest.mark.asyncio
    async def test_calculate_stats_without_data(self):
        """Test calculate_stats without data."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return []
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            result = await processor.calculate_stats('test_webhook')
            
            assert result == {}
    
    @pytest.mark.asyncio
    async def test_calculate_stats_with_none_client(self):
        """Test calculate_stats with None client."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        processor.client = None
        
        result = await processor.calculate_stats('test_webhook')
        
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_calculate_stats_validation_error(self):
        """Test calculate_stats with validation error."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        processor.client = Mock()
        
        # Invalid webhook_id that will fail validation
        with pytest.raises(ValueError):
            await processor.calculate_stats('webhook;id')  # Contains semicolon
    
    @pytest.mark.asyncio
    async def test_calculate_stats_exception(self):
        """Test calculate_stats with exception."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=Exception("Query failed"))
            
            with patch('builtins.print'):
                result = await processor.calculate_stats('test_webhook')
                
                assert result == {}


class TestAnalyticsProcessorProcessAndSaveStats:
    """Test AnalyticsProcessor.process_and_save_stats() - main processing loop."""
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_success(self):
        """Test successful process_and_save_stats."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        mock_analytics = AsyncMock()
        mock_analytics.save_stats = AsyncMock()
        processor.analytics = mock_analytics
        
        # Mock get_all_webhook_ids to return some IDs
        with patch.object(processor, 'get_all_webhook_ids', return_value=['webhook1', 'webhook2']):
            # Mock calculate_stats to return stats
            with patch.object(processor, 'calculate_stats', return_value={'total': 100}):
                await processor.process_and_save_stats()
                
                mock_analytics.save_stats.assert_called_once()
                call_args = mock_analytics.save_stats.call_args[0][0]
                assert 'webhook1' in call_args
                assert 'webhook2' in call_args
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_no_webhook_ids(self):
        """Test process_and_save_stats with no webhook IDs."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        mock_analytics = AsyncMock()
        mock_analytics.save_stats = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch.object(processor, 'get_all_webhook_ids', return_value=[]):
            with patch('builtins.print'):
                await processor.process_and_save_stats()
                
                # Should not call save_stats
                mock_analytics.save_stats.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_no_client(self):
        """Test process_and_save_stats with no client."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        processor.client = None
        processor.analytics = Mock()
        
        # Should return early
        await processor.process_and_save_stats()
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_no_analytics(self):
        """Test process_and_save_stats with no analytics."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        processor.analytics = None
        
        # Should return early
        await processor.process_and_save_stats()
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_empty_stats(self):
        """Test process_and_save_stats with empty stats."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        mock_analytics = AsyncMock()
        mock_analytics.save_stats = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch.object(processor, 'get_all_webhook_ids', return_value=['webhook1']):
            # Mock calculate_stats to return empty dict
            with patch.object(processor, 'calculate_stats', return_value={}):
                await processor.process_and_save_stats()
                
                # Should not call save_stats if stats are empty
                mock_analytics.save_stats.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_process_and_save_stats_exception(self):
        """Test process_and_save_stats with exception."""
        config = {'host': 'localhost'}
        processor = AnalyticsProcessor(config)
        
        mock_client = Mock()
        processor.client = mock_client
        
        mock_analytics = AsyncMock()
        processor.analytics = mock_analytics
        
        with patch.object(processor, 'get_all_webhook_ids', side_effect=Exception("Processing failed")):
            with patch('builtins.print'):
                # Should not raise exception
                await processor.process_and_save_stats()


class TestAnalyticsProcessingLoop:
    """Test analytics_processing_loop() function."""
    
    @pytest.mark.asyncio
    async def test_analytics_processing_loop_with_clickhouse_config(self):
        """Test analytics_processing_loop with ClickHouse config."""
        mock_config = {
            'clickhouse1': {
                'type': 'clickhouse',
                'host': 'localhost',
                'port': 9000
            }
        }
        
        mock_processor = AsyncMock()
        mock_processor.connect = AsyncMock()
        mock_processor.process_and_save_stats = AsyncMock()
        mock_processor.disconnect = AsyncMock()
        
        with patch('src.analytics_processor.load_env_vars', return_value=mock_config), \
             patch('src.analytics_processor.AnalyticsProcessor', return_value=mock_processor), \
             patch('asyncio.sleep', side_effect=KeyboardInterrupt()), \
             patch('builtins.print'):
            
            try:
                await analytics_processing_loop()
            except KeyboardInterrupt:
                pass
            
            mock_processor.connect.assert_called_once()
            mock_processor.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analytics_processing_loop_no_clickhouse_config(self):
        """Test analytics_processing_loop without ClickHouse config."""
        mock_config = {
            'postgres1': {
                'type': 'postgresql',
                'host': 'localhost'
            }
        }
        
        with patch('src.analytics_processor.load_env_vars', return_value=mock_config), \
             patch('builtins.print'):
            
            await analytics_processing_loop()
            
            # Should return early without creating processor
    
    @pytest.mark.asyncio
    async def test_analytics_processing_loop_exception(self):
        """Test analytics_processing_loop with exception."""
        mock_config = {
            'clickhouse1': {
                'type': 'clickhouse',
                'host': 'localhost',
                'port': 9000
            }
        }
        
        mock_processor = AsyncMock()
        mock_processor.connect = AsyncMock(side_effect=Exception("Connection failed"))
        mock_processor.disconnect = AsyncMock()
        
        with patch('src.analytics_processor.load_env_vars', return_value=mock_config), \
             patch('src.analytics_processor.AnalyticsProcessor', return_value=mock_processor), \
             patch('builtins.print'):
            
            await analytics_processing_loop()
            
            mock_processor.disconnect.assert_called_once()

