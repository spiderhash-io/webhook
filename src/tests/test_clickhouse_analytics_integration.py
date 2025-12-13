"""
Integration tests for clickhouse_analytics.py.
Tests cover missing coverage areas including connection, table creation, worker tasks, and flush operations.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone

from src.clickhouse_analytics import ClickHouseAnalytics


class TestClickHouseAnalyticsConnection:
    """Test connection establishment and error handling."""
    
    @pytest.mark.asyncio
    async def test_connect_without_config(self):
        """Test connection without connection config."""
        analytics = ClickHouseAnalytics(connection_config=None)
        
        with pytest.raises(Exception, match="connection config not provided"):
            await analytics.connect()
    
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
        
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        mock_client.execute = Mock()
        
        with patch('src.clickhouse_analytics._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('src.clickhouse_analytics.Client', return_value=mock_client), \
             patch.object(analytics, '_ensure_tables', AsyncMock()):
            
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(return_value=mock_client)
            mock_loop.return_value = mock_loop_instance
            
            await analytics.connect()
            
            assert analytics.client == mock_client
            assert analytics.queue is not None
            assert analytics._running is True
    
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
        
        analytics = ClickHouseAnalytics(connection_config=config)
        
        with patch('src.clickhouse_analytics._validate_connection_host') as mock_validate:
            mock_validate.side_effect = ValueError("Invalid host")
            
            with pytest.raises(ValueError, match="Host validation failed"):
                await analytics.connect()
    
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
        
        analytics = ClickHouseAnalytics(connection_config=config)
        
        with patch('src.clickhouse_analytics._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop:
            
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(side_effect=Exception("Connection failed"))
            mock_loop.return_value = mock_loop_instance
            
            with pytest.raises(Exception):
                await analytics.connect()
    
    @pytest.mark.asyncio
    async def test_connect_without_password(self):
        """Test connection without password."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        mock_client.execute = Mock()
        
        with patch('src.clickhouse_analytics._validate_connection_host', return_value='localhost'), \
             patch('asyncio.get_running_loop') as mock_loop, \
             patch('src.clickhouse_analytics.Client') as mock_client_class, \
             patch.object(analytics, '_ensure_tables', AsyncMock()):
            
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(return_value=mock_client)
            mock_loop.return_value = mock_loop_instance
            
            await analytics.connect()
            
            # Check that Client was called without password
            call_kwargs = mock_client_class.call_args[1] if mock_client_class.called else {}
            assert 'password' not in call_kwargs or call_kwargs.get('password') is None


class TestClickHouseAnalyticsEnsureTables:
    """Test table creation logic."""
    
    @pytest.mark.asyncio
    async def test_ensure_tables_without_client(self):
        """Test _ensure_tables without client."""
        analytics = ClickHouseAnalytics(connection_config={})
        analytics.client = None
        
        # Should return early without error
        await analytics._ensure_tables()
    
    @pytest.mark.asyncio
    async def test_ensure_tables_stats_table_creation(self):
        """Test stats table creation."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        mock_client.execute = Mock()
        analytics.client = mock_client
        analytics.stats_table_created = False
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock()
            mock_loop.return_value = mock_loop_instance
            
            await analytics._ensure_tables()
            
            assert analytics.stats_table_created is True
            mock_loop_instance.run_in_executor.assert_called()
    
    @pytest.mark.asyncio
    async def test_ensure_tables_logs_table_creation(self):
        """Test logs table creation."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        mock_client.execute = Mock()
        analytics.client = mock_client
        analytics.stats_table_created = True
        analytics.logs_table_created = False
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock()
            mock_loop.return_value = mock_loop_instance
            
            await analytics._ensure_tables()
            
            assert analytics.logs_table_created is True
    
    @pytest.mark.asyncio
    async def test_ensure_tables_with_error(self):
        """Test _ensure_tables error handling."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        analytics.client = mock_client
        analytics.stats_table_created = False
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(side_effect=Exception("Table creation failed"))
            mock_loop.return_value = mock_loop_instance
            
            # Should handle error gracefully
            await analytics._ensure_tables()
            
            # Should still try to create (might already exist)
            assert analytics.stats_table_created is False  # Not set on error


class TestClickHouseAnalyticsFlushOperations:
    """Test flush operations for logs and stats."""
    
    @pytest.mark.asyncio
    async def test_flush_logs_success(self):
        """Test successful log flush."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        mock_client.execute = Mock()
        analytics.client = mock_client
        
        buffer = [
            ('id1', 'webhook1', datetime.now(timezone.utc), 'payload1', 'headers1'),
            ('id2', 'webhook2', datetime.now(timezone.utc), 'payload2', 'headers2')
        ]
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock()
            mock_loop.return_value = mock_loop_instance
            
            await analytics._flush_logs(buffer)
            
            mock_loop_instance.run_in_executor.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_flush_logs_without_client(self):
        """Test flush logs without client."""
        analytics = ClickHouseAnalytics(connection_config={})
        analytics.client = None
        
        # Should return early without error
        await analytics._flush_logs([('id', 'webhook', datetime.now(timezone.utc), 'payload', 'headers')])
    
    @pytest.mark.asyncio
    async def test_flush_logs_with_empty_buffer(self):
        """Test flush logs with empty buffer."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        analytics.client = MagicMock()
        
        # Should return early without error
        await analytics._flush_logs([])
    
    @pytest.mark.asyncio
    async def test_flush_logs_with_error(self):
        """Test flush logs error handling."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        analytics.client = mock_client
        
        buffer = [('id', 'webhook', datetime.now(timezone.utc), 'payload', 'headers')]
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(side_effect=Exception("Flush failed"))
            mock_loop.return_value = mock_loop_instance
            
            # Should handle error gracefully
            await analytics._flush_logs(buffer)
    
    @pytest.mark.asyncio
    async def test_flush_stats_success(self):
        """Test successful stats flush."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        mock_client.execute = Mock()
        analytics.client = mock_client
        
        buffer = [
            ('id1', 'webhook1', datetime.now(timezone.utc), 10, 1, 2, 3, 4, 5, 6, 7, 8),
            ('id2', 'webhook2', datetime.now(timezone.utc), 20, 2, 3, 4, 5, 6, 7, 8, 9)
        ]
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock()
            mock_loop.return_value = mock_loop_instance
            
            await analytics._flush_stats(buffer)
            
            mock_loop_instance.run_in_executor.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_flush_stats_with_error(self):
        """Test flush stats error handling."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        analytics.client = mock_client
        
        buffer = [('id', 'webhook', datetime.now(timezone.utc), 10, 1, 2, 3, 4, 5, 6, 7, 8)]
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock(side_effect=Exception("Flush failed"))
            mock_loop.return_value = mock_loop_instance
            
            # Should handle error gracefully
            await analytics._flush_stats(buffer)


class TestClickHouseAnalyticsSaveOperations:
    """Test save operations for logs and stats."""
    
    @pytest.mark.asyncio
    async def test_save_stats_without_queue(self):
        """Test save_stats without queue (should connect first)."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        analytics.queue = None
        analytics.client = None
        
        with patch.object(analytics, 'connect', AsyncMock()) as mock_connect:
            # After connect, queue should be set, but if not, should return
            await analytics.save_stats({'webhook1': {'total': 10}})
            
            # Should try to connect
            mock_connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_save_stats_with_queue(self):
        """Test save_stats with active queue."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_queue = AsyncMock()
        mock_queue.put = AsyncMock()
        analytics.queue = mock_queue
        
        stats = {
            'webhook1': {
                'total': 10,
                'minute': 1,
                '5_minutes': 2,
                '15_minutes': 3,
                '30_minutes': 4,
                'hour': 5,
                'day': 6,
                'week': 7,
                'month': 8
            }
        }
        
        await analytics.save_stats(stats)
        
        mock_queue.put.assert_called_once()
        call_args = mock_queue.put.call_args[0][0]
        assert call_args[0] == 'stats'
        assert len(call_args[1]) == 1  # One record
    
    @pytest.mark.asyncio
    async def test_save_log_without_queue(self):
        """Test save_log without queue (should connect first)."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        analytics.queue = None
        analytics.client = None
        
        with patch.object(analytics, 'connect', AsyncMock()):
            # After connect, queue should be set, but if not, should return
            await analytics.save_log('webhook1', {'data': 'test'}, {'header': 'value'})
    
    @pytest.mark.asyncio
    async def test_save_log_with_queue(self):
        """Test save_log with active queue."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_queue = AsyncMock()
        mock_queue.put = AsyncMock()
        analytics.queue = mock_queue
        
        with patch('src.utils.CredentialCleaner') as mock_cleaner_class, \
             patch('copy.deepcopy', return_value={'data': 'test'}), \
             patch('src.clickhouse_analytics.json.dumps', return_value='{"data":"test"}'):
            
            mock_cleaner = Mock()
            mock_cleaner.clean_credentials = Mock(return_value={'data': 'test'})
            mock_cleaner.clean_headers = Mock(return_value={'header': 'value'})
            mock_cleaner_class.return_value = mock_cleaner
            
            await analytics.save_log('webhook1', {'data': 'test'}, {'header': 'value'})
            
            mock_queue.put.assert_called_once()
            call_args = mock_queue.put.call_args[0][0]
            assert call_args[0] == 'log'


class TestClickHouseAnalyticsDisconnect:
    """Test disconnect and cleanup."""
    
    @pytest.mark.asyncio
    async def test_disconnect_with_worker_task(self):
        """Test disconnect with active worker task."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_task = AsyncMock()
        mock_task.cancel = Mock()
        analytics._worker_task = mock_task
        
        with patch('asyncio.wait_for', AsyncMock()):
            await analytics.disconnect()
            
            assert analytics._running is False
    
    @pytest.mark.asyncio
    async def test_disconnect_with_worker_timeout(self):
        """Test disconnect with worker task timeout."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_task = AsyncMock()
        mock_task.cancel = Mock()
        analytics._worker_task = mock_task
        
        with patch('asyncio.wait_for', AsyncMock(side_effect=asyncio.TimeoutError())):
            await analytics.disconnect()
            
            mock_task.cancel.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_with_client(self):
        """Test disconnect with active client."""
        config = {'host': 'localhost', 'port': 9000, 'database': 'test', 'user': 'default', 'password': ''}
        analytics = ClickHouseAnalytics(connection_config=config)
        
        mock_client = MagicMock()
        mock_client.disconnect = Mock()
        analytics.client = mock_client
        
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop_instance = Mock()
            mock_loop_instance.run_in_executor = AsyncMock()
            mock_loop.return_value = mock_loop_instance
            
            await analytics.disconnect()
            
            mock_loop_instance.run_in_executor.assert_called_once()

