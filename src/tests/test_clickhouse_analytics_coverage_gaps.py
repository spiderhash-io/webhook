"""
Comprehensive unit tests to fill coverage gaps in clickhouse_analytics.py.
Target: 100% coverage for ClickHouseAnalytics class.
"""
import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from src.clickhouse_analytics import ClickHouseAnalytics


class TestClickHouseAnalyticsInit:
    """Test ClickHouseAnalytics.__init__() - various configs."""
    
    def test_init_with_full_config(self):
        """Test initialization with full configuration."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }
        analytics = ClickHouseAnalytics(config)
        assert analytics.connection_config == config
        assert analytics.client is None
        assert analytics.stats_table_created is False
        assert analytics.logs_table_created is False
        assert analytics.batch_size == 1000
        assert analytics.flush_interval == 2.0
    
    def test_init_with_custom_batch_size(self):
        """Test initialization with custom batch size."""
        config = {'host': 'localhost'}
        analytics = ClickHouseAnalytics(config, batch_size=500)
        assert analytics.batch_size == 500
    
    def test_init_with_custom_flush_interval(self):
        """Test initialization with custom flush interval."""
        config = {'host': 'localhost'}
        analytics = ClickHouseAnalytics(config, flush_interval=5.0)
        assert analytics.flush_interval == 5.0
    
    def test_init_with_none_config(self):
        """Test initialization with None config."""
        analytics = ClickHouseAnalytics(None)
        assert analytics.connection_config is None


class TestClickHouseAnalyticsConnect:
    """Test ClickHouseAnalytics.connect() - connection success/failure."""
    
    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful connection."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }
        analytics = ClickHouseAnalytics(config)
        
        mock_client = Mock()
        mock_client.execute = Mock()
        
        with patch('src.config._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('asyncio.create_task') as mock_create_task, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            mock_loop.return_value.run_in_executor.side_effect = [
                mock_client,  # First call for create_client
                None,  # Second call for execute('SELECT 1')
                None,  # Third call for _ensure_tables stats table
                None,  # Fourth call for _ensure_tables logs table
            ]
            
            await analytics.connect()
            
            assert analytics.client is not None
            assert analytics.queue is not None
            assert analytics._running is True
    
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
        analytics = ClickHouseAnalytics(config)
        
        mock_client = Mock()
        mock_client.execute = Mock()
        
        with patch('src.config._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('asyncio.create_task') as mock_create_task, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            mock_loop.return_value.run_in_executor.side_effect = [
                mock_client,
                None,
                None,
                None,
            ]
            
            await analytics.connect()
            
            assert analytics.client is not None
    
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
        analytics = ClickHouseAnalytics(config)
        
        mock_client = Mock()
        mock_client.execute = Mock()
        
        with patch('src.config._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('asyncio.create_task') as mock_create_task, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            mock_loop.return_value.run_in_executor.side_effect = [
                mock_client,
                None,
                None,
                None,
            ]
            
            await analytics.connect()
            
            assert analytics.client is not None
    
    @pytest.mark.asyncio
    async def test_connect_no_config(self):
        """Test connection without config."""
        analytics = ClickHouseAnalytics(None)
        
        with pytest.raises(Exception, match="ClickHouse connection config not provided"):
            await analytics.connect()
    
    @pytest.mark.asyncio
    async def test_connect_host_validation_failure(self):
        """Test connection failure due to host validation."""
        config = {
            'host': '192.168.1.1',
            'port': 9000
        }
        analytics = ClickHouseAnalytics(config)
        
        with patch('src.config._validate_connection_host', side_effect=ValueError("Invalid host")):
            with pytest.raises(ValueError, match="Host validation failed"):
                await analytics.connect()
    
    @pytest.mark.asyncio
    async def test_connect_client_creation_failure(self):
        """Test connection failure during client creation."""
        config = {
            'host': 'localhost',
            'port': 9000
        }
        analytics = ClickHouseAnalytics(config)
        
        with patch('src.config._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop:
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=Exception("Connection failed"))
            
            with patch('builtins.print'):
                with pytest.raises(Exception):
                    await analytics.connect()


class TestClickHouseAnalyticsEnsureTables:
    """Test ClickHouseAnalytics._ensure_tables() - table creation."""
    
    @pytest.mark.asyncio
    async def test_ensure_tables_success(self):
        """Test successful table creation."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        analytics.client.execute = Mock()
        
        with patch('asyncio.get_running_loop') as mock_loop, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await analytics._ensure_tables()
            
            assert analytics.stats_table_created is True
            assert analytics.logs_table_created is True
    
    @pytest.mark.asyncio
    async def test_ensure_tables_no_client(self):
        """Test _ensure_tables with no client."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = None
        
        await analytics._ensure_tables()
        
        # Should return early without creating tables
        assert analytics.stats_table_created is False
        assert analytics.logs_table_created is False
    
    @pytest.mark.asyncio
    async def test_ensure_tables_stats_table_already_exists(self):
        """Test _ensure_tables when stats table already exists."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        analytics.stats_table_created = True
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await analytics._ensure_tables()
            
            # Should only create logs table
            assert analytics.logs_table_created is True
    
    @pytest.mark.asyncio
    async def test_ensure_tables_exception(self):
        """Test _ensure_tables with exception."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        analytics.client.execute = Mock(side_effect=Exception("Table creation failed"))
        
        with patch('asyncio.get_running_loop') as mock_loop, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                raise Exception("Table creation failed")
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            # Should not raise exception
            await analytics._ensure_tables()


class TestClickHouseAnalyticsSaveLog:
    """Test ClickHouseAnalytics.save_log() - successful save and error handling."""
    
    @pytest.mark.asyncio
    async def test_save_log_success(self):
        """Test successful save_log."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        payload = {'data': 'test'}
        headers = {'Content-Type': 'application/json'}
        
        await analytics.save_log('test_webhook', payload, headers)
        
        # Check that item was queued
        assert not analytics.queue.empty()
        item = await analytics.queue.get()
        assert item[0] == 'log'
        log_data = item[1]
        assert log_data[1] == 'test_webhook'  # webhook_id
    
    @pytest.mark.asyncio
    async def test_save_log_with_list_payload(self):
        """Test save_log with list payload."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        payload = [1, 2, 3]
        headers = {}
        
        await analytics.save_log('test_webhook', payload, headers)
        
        assert not analytics.queue.empty()
    
    @pytest.mark.asyncio
    async def test_save_log_with_string_payload(self):
        """Test save_log with string payload."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        payload = 'test string'
        headers = {}
        
        await analytics.save_log('test_webhook', payload, headers)
        
        assert not analytics.queue.empty()
    
    @pytest.mark.asyncio
    async def test_save_log_with_recursive_payload(self):
        """Test save_log with recursive payload."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Create recursive structure
        payload = {}
        payload['self'] = payload
        
        await analytics.save_log('test_webhook', payload, {})
        
        # Should handle recursion error gracefully
        assert not analytics.queue.empty()
        item = await analytics.queue.get()
        log_data = item[1]
        payload_str = log_data[3]
        # Should contain error message about recursion
        assert 'error' in json.loads(payload_str).lower() or 'too deeply nested' in payload_str.lower()
    
    @pytest.mark.asyncio
    async def test_save_log_auto_connect(self):
        """Test save_log automatically connects if queue not initialized."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = None
        analytics.client = None
        
        mock_client = Mock()
        mock_client.execute = Mock()
        
        with patch.object(analytics, 'connect', new_callable=AsyncMock) as mock_connect:
            # After connect, queue should be set
            async def connect_side_effect():
                analytics.queue = asyncio.Queue()
                analytics._running = True
            
            mock_connect.side_effect = connect_side_effect
            
            await analytics.save_log('test_webhook', {'data': 'test'}, {})
            
            mock_connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_save_log_exception(self):
        """Test save_log with exception."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Mock queue.put to raise exception
        with patch.object(analytics.queue, 'put', side_effect=Exception("Queue error")), \
             patch('builtins.print'):
            
            # Should not raise exception
            await analytics.save_log('test_webhook', {'data': 'test'}, {})


class TestClickHouseAnalyticsSaveStats:
    """Test ClickHouseAnalytics.save_stats() - successful save and error handling."""
    
    @pytest.mark.asyncio
    async def test_save_stats_success(self):
        """Test successful save_stats."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        stats = {
            'webhook1': {
                'total': 100,
                'minute': 10,
                '5_minutes': 50,
                '15_minutes': 150,
                '30_minutes': 300,
                'hour': 500,
                'day': 800,
                'week': 900,
                'month': 950
            }
        }
        
        await analytics.save_stats(stats)
        
        assert not analytics.queue.empty()
        item = await analytics.queue.get()
        assert item[0] == 'stats'
        records = item[1]
        assert len(records) == 1
        assert records[0][1] == 'webhook1'  # webhook_id
    
    @pytest.mark.asyncio
    async def test_save_stats_with_missing_fields(self):
        """Test save_stats with missing stat fields."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        stats = {
            'webhook1': {
                'total': 100
                # Missing other fields
            }
        }
        
        await analytics.save_stats(stats)
        
        assert not analytics.queue.empty()
        item = await analytics.queue.get()
        records = item[1]
        # Missing fields should default to 0
        assert records[0][3] == 100  # total
        assert records[0][4] == 0  # minute (default)
    
    @pytest.mark.asyncio
    async def test_save_stats_empty_dict(self):
        """Test save_stats with empty dict."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        await analytics.save_stats({})
        
        # Should not add anything to queue
        assert analytics.queue.empty()
    
    @pytest.mark.asyncio
    async def test_save_stats_auto_connect(self):
        """Test save_stats automatically connects if queue not initialized."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = None
        analytics.client = None
        
        with patch.object(analytics, 'connect', new_callable=AsyncMock) as mock_connect:
            async def connect_side_effect():
                analytics.queue = asyncio.Queue()
                analytics._running = True
            
            mock_connect.side_effect = connect_side_effect
            
            await analytics.save_stats({'webhook1': {'total': 100}})
            
            mock_connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_save_stats_exception(self):
        """Test save_stats with exception."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Mock queue.put to raise exception
        with patch.object(analytics.queue, 'put', side_effect=Exception("Queue error")), \
             patch('builtins.print'):
            
            # Should not raise exception
            await analytics.save_stats({'webhook1': {'total': 100}})


class TestClickHouseAnalyticsDisconnect:
    """Test ClickHouseAnalytics.disconnect() - all paths."""
    
    @pytest.mark.asyncio
    async def test_disconnect_success(self):
        """Test successful disconnect."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics._running = True
        analytics.client = Mock()
        analytics.client.disconnect = Mock()
        
        # Create a mock worker task that completes immediately
        async def mock_worker():
            await asyncio.sleep(0.01)
        
        analytics._worker_task = asyncio.create_task(mock_worker())
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await analytics.disconnect()
            
            assert analytics._running is False
            analytics.client.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_with_timeout(self):
        """Test disconnect with worker timeout."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics._running = True
        analytics.client = Mock()
        analytics.client.disconnect = Mock()
        
        # Create a worker task that takes too long
        async def slow_worker():
            await asyncio.sleep(10)
        
        analytics._worker_task = asyncio.create_task(slow_worker())
        
        with patch('asyncio.get_running_loop') as mock_loop, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await analytics.disconnect()
            
            # Worker should be cancelled
            assert analytics._worker_task.cancelled()
    
    @pytest.mark.asyncio
    async def test_disconnect_no_worker_task(self):
        """Test disconnect without worker task."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics._running = True
        analytics._worker_task = None
        analytics.client = Mock()
        analytics.client.disconnect = Mock()
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await analytics.disconnect()
            
            analytics.client.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_no_client(self):
        """Test disconnect without client."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics._running = True
        analytics.client = None
        analytics._worker_task = None
        
        # Should not raise exception
        await analytics.disconnect()
    
    @pytest.mark.asyncio
    async def test_disconnect_client_exception(self):
        """Test disconnect when client.disconnect() raises exception."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics._running = True
        analytics.client = Mock()
        analytics.client.disconnect = Mock(side_effect=Exception("Disconnect failed"))
        analytics._worker_task = None
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            # Should not raise exception
            await analytics.disconnect()


class TestClickHouseAnalyticsFlush:
    """Test ClickHouseAnalytics flush methods."""
    
    @pytest.mark.asyncio
    async def test_flush_logs_success(self):
        """Test successful _flush_logs."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        analytics.client.execute = Mock()
        
        buffer = [
            ('id1', 'webhook1', datetime.now(timezone.utc), '{"data": "test"}', '{"header": "value"}')
        ]
        
        with patch('asyncio.get_running_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await analytics._flush_logs(buffer)
            
            analytics.client.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_flush_logs_no_client(self):
        """Test _flush_logs with no client."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = None
        
        buffer = [('id1', 'webhook1', datetime.now(timezone.utc), '{}', '{}')]
        
        # Should return early
        await analytics._flush_logs(buffer)
    
    @pytest.mark.asyncio
    async def test_flush_logs_empty_buffer(self):
        """Test _flush_logs with empty buffer."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        
        # Should return early
        await analytics._flush_logs([])
    
    @pytest.mark.asyncio
    async def test_flush_logs_exception(self):
        """Test _flush_logs with exception."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        analytics.client.execute = Mock(side_effect=Exception("Execute failed"))
        
        buffer = [('id1', 'webhook1', datetime.now(timezone.utc), '{}', '{}')]
        
        with patch('asyncio.get_running_loop') as mock_loop, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                raise Exception("Execute failed")
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            # Should not raise exception
            await analytics._flush_logs(buffer)
    
    @pytest.mark.asyncio
    async def test_flush_stats_success(self):
        """Test successful _flush_stats."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        analytics.client.execute = Mock()
        
        buffer = [
            ('id1', 'webhook1', datetime.now(timezone.utc), 100, 10, 20, 30, 40, 50, 60, 70, 80)
        ]
        
        with patch('asyncio.get_running_loop') as mock_loop, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                return None
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            await analytics._flush_stats(buffer)
            
            analytics.client.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_flush_stats_no_client(self):
        """Test _flush_stats with no client."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = None
        
        buffer = [('id1', 'webhook1', datetime.now(timezone.utc), 100, 0, 0, 0, 0, 0, 0, 0, 0)]
        
        # Should return early
        await analytics._flush_stats(buffer)
    
    @pytest.mark.asyncio
    async def test_flush_stats_empty_buffer(self):
        """Test _flush_stats with empty buffer."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        
        # Should return early
        await analytics._flush_stats([])
    
    @pytest.mark.asyncio
    async def test_flush_stats_exception(self):
        """Test _flush_stats with exception."""
        analytics = ClickHouseAnalytics({'host': 'localhost'})
        analytics.client = Mock()
        analytics.client.execute = Mock(side_effect=Exception("Execute failed"))
        
        buffer = [('id1', 'webhook1', datetime.now(timezone.utc), 100, 0, 0, 0, 0, 0, 0, 0, 0)]
        
        with patch('asyncio.get_running_loop') as mock_loop, \
             patch('builtins.print'):
            
            async def run_executor_mock(executor, func):
                if callable(func):
                    return func()
                raise Exception("Execute failed")
            
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=run_executor_mock)
            
            # Should not raise exception
            await analytics._flush_stats(buffer)

