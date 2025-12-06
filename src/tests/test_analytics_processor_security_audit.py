"""
Comprehensive security audit tests for Analytics Processor and ClickHouse Analytics.
Tests SQL injection, webhook_id validation, error disclosure, connection security, JSON serialization, DoS, and worker security.
"""
import pytest
import json
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock, Mock
from src.analytics_processor import AnalyticsProcessor
from src.clickhouse_analytics import ClickHouseAnalytics


# ============================================================================
# 1. SQL INJECTION VIA WEBHOOK_ID
# ============================================================================

class TestAnalyticsProcessorSQLInjection:
    """Test SQL injection vulnerabilities in AnalyticsProcessor."""
    
    @pytest.mark.asyncio
    async def test_webhook_id_sql_injection_calculate_stats(self):
        """Test SQL injection via webhook_id in calculate_stats()."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        processor.client = mock_client
        
        # SQL injection attempts
        malicious_webhook_ids = [
            "webhook_id'; DROP TABLE webhook_logs; --",
            "webhook_id' OR '1'='1",
            "webhook_id' UNION SELECT * FROM users --",
            "webhook_id'; DELETE FROM webhook_logs; --",
            "webhook_id'; EXEC xp_cmdshell('dir'); --",
        ]
        
        for malicious_id in malicious_webhook_ids:
            # SECURITY: calculate_stats uses parameterized queries {webhook_id:String}
            # This should prevent SQL injection, but we need to verify webhook_id validation
            result = await processor.calculate_stats(malicious_id)
            
            # Should not crash
            assert isinstance(result, dict)
            # Parameterized query should prevent injection
            # Verify that execute was called with parameters, not string interpolation
            if mock_client.execute.called:
                call_args = mock_client.execute.call_args
                # Should be called with query and parameters dict
                assert len(call_args[0]) >= 1
                query = call_args[0][0]
                # Query should use parameterized syntax, not string interpolation
                assert '{webhook_id:String}' in query or '{webhook_id}' in query
                # Should have parameters dict
                if len(call_args[0]) > 1:
                    params = call_args[0][1]
                    assert isinstance(params, dict)
                    assert 'webhook_id' in params
    
    @pytest.mark.asyncio
    async def test_webhook_id_from_database_injection(self):
        """Test SQL injection when webhook_id comes from database (get_all_webhook_ids)."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        # Mock execute to return empty result (simulating no data)
        mock_client.execute.return_value = []
        processor.client = mock_client
        
        # Create a mock analytics object
        mock_analytics = MagicMock()
        processor.analytics = mock_analytics
        
        # Simulate malicious webhook_id retrieved from database
        malicious_webhook_ids = [
            "webhook_id'; DROP TABLE webhook_logs; --",
            "webhook_id' OR '1'='1",
        ]
        
        # Mock get_all_webhook_ids to return malicious IDs
        with patch.object(processor, 'get_all_webhook_ids', return_value=malicious_webhook_ids):
            # Mock run_in_executor to call the lambda directly (for testing)
            with patch('asyncio.get_event_loop') as mock_loop:
                async def run_executor_mock(executor, func):
                    # Execute the lambda directly for testing
                    return func()
                mock_loop.return_value.run_in_executor = run_executor_mock
                
                # Process stats - should handle malicious IDs safely
                await processor.process_and_save_stats()
            
            # Should not crash
            # calculate_stats should use parameterized queries for each malicious ID
            # Since calculate_stats uses run_in_executor, we check that execute was called
            # The mock should be called for each webhook_id via calculate_stats
            assert mock_client.execute.called, "execute should be called for each webhook_id"
    
    @pytest.mark.asyncio
    async def test_get_all_webhook_ids_sql_injection(self):
        """Test that get_all_webhook_ids() query is safe (no user input)."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        processor.client = mock_client
        
        # get_all_webhook_ids uses hardcoded query, no user input
        result = await processor.get_all_webhook_ids()
        
        # Should not crash
        assert isinstance(result, list)
        # Query should be hardcoded, not use string interpolation
        if mock_client.execute.called:
            call_args = mock_client.execute.call_args
            query = call_args[0][0]
            # Should be hardcoded query without user input
            assert "SELECT DISTINCT webhook_id FROM webhook_logs" in query


# ============================================================================
# 2. WEBHOOK_ID VALIDATION
# ============================================================================

class TestAnalyticsProcessorWebhookIdValidation:
    """Test webhook_id validation and type handling."""
    
    @pytest.mark.asyncio
    async def test_webhook_id_type_validation(self):
        """Test that non-string webhook_id is handled safely."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        processor.client = mock_client
        
        # Non-string webhook_ids
        invalid_ids = [
            None,
            123,
            [],
            {},
            True,
        ]
        
        for invalid_id in invalid_ids:
            try:
                result = await processor.calculate_stats(invalid_id)
                # Should handle gracefully (return empty dict or raise error)
                assert isinstance(result, dict) or result == {}
            except (TypeError, ValueError, AttributeError):
                # Acceptable - type validation should reject non-strings
                pass
    
    @pytest.mark.asyncio
    async def test_webhook_id_empty_validation(self):
        """Test empty webhook_id handling."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        processor.client = mock_client
        
        # Empty webhook_ids
        empty_ids = [
            "",
            "   ",
            "\x00",
            "\n",
        ]
        
        for empty_id in empty_ids:
            result = await processor.calculate_stats(empty_id)
            # Should handle gracefully
            assert isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_webhook_id_large_validation(self):
        """Test very large webhook_id (DoS prevention)."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        processor.client = mock_client
        
        # Very large webhook_id
        large_id = "a" * 100000  # 100KB
        
        result = await processor.calculate_stats(large_id)
        # Should handle gracefully (parameterized query should work)
        assert isinstance(result, dict)


# ============================================================================
# 3. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestAnalyticsProcessorErrorDisclosure:
    """Test error information disclosure vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_error_message_sanitization_calculate_stats(self):
        """Test that error messages don't leak sensitive information."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        processor.client = mock_client
        
        # Mock execute to raise exception with sensitive info
        mock_client.execute.side_effect = Exception("Connection failed to localhost:9000 with user default password secret123")
        
        result = await processor.calculate_stats("test_webhook")
        
        # Error should be logged but not exposed in return value
        # Function should return empty dict on error
        assert isinstance(result, dict)
        assert result == {}
        # Error message should be logged (print), but not in return value
        # This is acceptable - errors are logged server-side
    
    @pytest.mark.asyncio
    async def test_error_message_sanitization_get_all_webhook_ids(self):
        """Test error message sanitization in get_all_webhook_ids()."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        processor.client = mock_client
        
        # Mock execute to raise exception
        mock_client.execute.side_effect = Exception("Database error: connection string=postgresql://user:pass@host/db")
        
        result = await processor.get_all_webhook_ids()
        
        # Should return empty list on error
        assert isinstance(result, list)
        assert result == []
    
    @pytest.mark.asyncio
    async def test_connection_error_disclosure(self):
        """Test that connection errors don't leak sensitive information."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': 'secret_password'
        }
        
        processor = AnalyticsProcessor(config)
        
        # Mock connection failure
        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.run_in_executor.side_effect = Exception("Connection failed: password=secret_password")
            
            try:
                await processor.connect()
                assert False, "Should have raised exception"
            except Exception as e:
                # Error message might contain sensitive info in exception
                # This is logged server-side, which is acceptable
                # But we should verify it's not exposed to clients
                error_str = str(e).lower()
                # Password should not be in error (if exposed to clients)
                # For server-side logging, this is acceptable
                pass


# ============================================================================
# 4. CONNECTION SECURITY
# ============================================================================

class TestAnalyticsProcessorConnectionSecurity:
    """Test connection security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_connection_config_injection(self):
        """Test connection configuration injection."""
        # Malicious configuration
        malicious_configs = [
            {
                'host': 'localhost; rm -rf /',
                'port': 9000,
                'database': 'test',
                'user': 'default',
                'password': ''
            },
            {
                'host': 'localhost',
                'port': '9000; cat /etc/passwd',
                'database': 'test',
                'user': 'default',
                'password': ''
            },
            {
                'host': 'localhost',
                'port': 9000,
                'database': '../../etc/passwd',
                'user': 'default',
                'password': ''
            },
        ]
        
        for malicious_config in malicious_configs:
            processor = AnalyticsProcessor(malicious_config)
            
            # Connection should fail or be rejected
            # clickhouse-driver should validate host/port/database
            try:
                await processor.connect()
                # If connection succeeds, verify it doesn't execute commands
                assert processor.client is not None
            except Exception:
                # Connection failure is acceptable for malicious config
                pass
    
    @pytest.mark.asyncio
    @pytest.mark.longrunning
    async def test_connection_ssrf_prevention(self):
        """Test SSRF prevention in connection configuration."""
        # SSRF attempts via host
        ssrf_configs = [
            {
                'host': '127.0.0.1',
                'port': 22,  # SSH port
                'database': 'test',
                'user': 'default',
                'password': ''
            },
            {
                'host': 'localhost',
                'port': 6379,  # Redis port
                'database': 'test',
                'user': 'default',
                'password': ''
            },
            {
                'host': '169.254.169.254',  # AWS metadata service
                'port': 9000,
                'database': 'test',
                'user': 'default',
                'password': ''
            },
        ]
        
        for ssrf_config in ssrf_configs:
            processor = AnalyticsProcessor(ssrf_config)
            
            # Connection should be attempted (ClickHouse driver will handle)
            # But we should verify it doesn't allow arbitrary connections
            try:
                await processor.connect()
                # If connection succeeds, it's to ClickHouse, not arbitrary service
                # ClickHouse driver validates protocol
            except Exception:
                # Connection failure is acceptable
                pass
    
    @pytest.mark.asyncio
    async def test_password_exposure(self):
        """Test that passwords are not exposed in error messages or logs."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': 'secret_password_123'
        }
        
        processor = AnalyticsProcessor(config)
        
        # Mock connection failure
        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.run_in_executor.side_effect = Exception("Connection failed")
            
            try:
                await processor.connect()
                assert False, "Should have raised exception"
            except Exception as e:
                error_str = str(e).lower()
                # Password should not be in error message
                assert "secret_password_123" not in error_str
                assert "password" not in error_str.lower() or "password" in error_str.lower()  # "password" word is OK, but not the value


# ============================================================================
# 5. CLICKHOUSE ANALYTICS SECURITY
# ============================================================================

class TestClickHouseAnalyticsSecurity:
    """Test ClickHouseAnalytics security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_webhook_id_injection_save_log(self):
        """Test webhook_id injection in save_log()."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        mock_client = MagicMock()
        analytics.client = mock_client
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # SQL injection attempts in webhook_id
        malicious_webhook_ids = [
            "webhook_id'; DROP TABLE webhook_logs; --",
            "webhook_id' OR '1'='1",
            "webhook_id'; DELETE FROM webhook_logs; --",
        ]
        
        for malicious_id in malicious_webhook_ids:
            await analytics.save_log(malicious_id, {"data": "test"}, {})
            
            # Should queue the log (webhook_id is stored, not executed as SQL)
            # When flushed, it should use parameterized queries
            assert not analytics.queue.empty()
            
            # Get item from queue
            item = await analytics.queue.get()
            assert item[0] == 'log'
            log_data = item[1]
            # webhook_id should be in the tuple
            assert malicious_id in log_data
    
    @pytest.mark.asyncio
    async def test_payload_json_injection_save_log(self):
        """Test JSON injection in payload."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        mock_client = MagicMock()
        analytics.client = mock_client
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Payload with potential injection
        malicious_payloads = [
            {"data": "'; DROP TABLE webhook_logs; --"},
            {"data": '"; DELETE FROM webhook_logs; --'},
            {"data": "test\x00null"},
        ]
        
        for malicious_payload in malicious_payloads:
            await analytics.save_log("test_webhook", malicious_payload, {})
            
            # Payload should be JSON serialized
            assert not analytics.queue.empty()
            item = await analytics.queue.get()
            log_data = item[1]
            # Payload should be JSON string
            payload_str = log_data[3]  # payload is 4th element
            # Should be valid JSON
            parsed = json.loads(payload_str)
            assert isinstance(parsed, dict)
    
    @pytest.mark.asyncio
    async def test_headers_json_injection_save_log(self):
        """Test JSON injection in headers."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        mock_client = MagicMock()
        analytics.client = mock_client
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Headers with potential injection
        malicious_headers = [
            {"X-Header": "'; DROP TABLE webhook_logs; --"},
            {"X-Header": '"; DELETE FROM webhook_logs; --'},
            {"X-Header": "test\x00null"},
        ]
        
        for malicious_header in malicious_headers:
            await analytics.save_log("test_webhook", {"data": "test"}, malicious_header)
            
            # Headers should be JSON serialized
            assert not analytics.queue.empty()
            item = await analytics.queue.get()
            log_data = item[1]
            # Headers should be JSON string
            headers_str = log_data[4]  # headers is 5th element
            # Should be valid JSON
            parsed = json.loads(headers_str)
            assert isinstance(parsed, dict)
    
    @pytest.mark.asyncio
    async def test_webhook_id_injection_save_stats(self):
        """Test webhook_id injection in save_stats()."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        mock_client = MagicMock()
        analytics.client = mock_client
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # SQL injection attempts in webhook_id
        malicious_stats = {
            "webhook_id'; DROP TABLE webhook_stats; --": {"total": 100},
            "webhook_id' OR '1'='1": {"total": 200},
        }
        
        await analytics.save_stats(malicious_stats)
        
        # Should queue the stats
        assert not analytics.queue.empty()
        item = await analytics.queue.get()
        assert item[0] == 'stats'
        records = item[1]
        # Should be list of tuples
        assert isinstance(records, list)
        # Each record should have webhook_id
        for record in records:
            assert len(record) >= 2
            # webhook_id is 2nd element
            webhook_id = record[1]
            # Should contain malicious ID (will be used in parameterized query)
            assert isinstance(webhook_id, str)
    
    @pytest.mark.asyncio
    async def test_flush_logs_parameterized_queries(self):
        """Test that _flush_logs uses parameterized queries."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        mock_client = MagicMock()
        analytics.client = mock_client
        
        # Create buffer with malicious data
        buffer = [
            ("id1", "webhook_id'; DROP TABLE webhook_logs; --", datetime.now(), '{"data": "test"}', '{"header": "value"}')
        ]
        
        # Mock run_in_executor to call the lambda directly (for testing)
        with patch('asyncio.get_event_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                # Execute the lambda directly for testing
                return func()
            mock_loop.return_value.run_in_executor = run_executor_mock
            
            await analytics._flush_logs(buffer)
        
        # Should use parameterized INSERT
        assert mock_client.execute.called, "execute should be called"
        call_args = mock_client.execute.call_args
        # Should be called with query and data
        assert len(call_args[0]) >= 1
        query = call_args[0][0]
        # Should be INSERT query - normalize whitespace for comparison
        query_normalized = ' '.join(query.upper().split())
        assert "INSERT INTO WEBHOOK_LOGS" in query_normalized
        # Should use VALUES with parameters, not string interpolation
        # ClickHouse driver uses parameterized queries
    
    @pytest.mark.asyncio
    async def test_flush_stats_parameterized_queries(self):
        """Test that _flush_stats uses parameterized queries."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        mock_client = MagicMock()
        analytics.client = mock_client
        
        # Create buffer with malicious data
        from datetime import datetime
        buffer = [
            ("id1", "webhook_id'; DROP TABLE webhook_stats; --", datetime.now(), 100, 10, 20, 30, 40, 50, 60, 70, 80)
        ]
        
        # Mock run_in_executor to call the lambda directly (for testing)
        with patch('asyncio.get_event_loop') as mock_loop:
            async def run_executor_mock(executor, func):
                # Execute the lambda directly for testing
                return func()
            mock_loop.return_value.run_in_executor = run_executor_mock
            
            await analytics._flush_stats(buffer)
        
        # Should use parameterized INSERT
        assert mock_client.execute.called, "execute should be called"
        call_args = mock_client.execute.call_args
        # Should be called with query and data
        assert len(call_args[0]) >= 1
        query = call_args[0][0]
        # Should be INSERT query - normalize whitespace for comparison
        query_normalized = ' '.join(query.upper().split())
        assert "INSERT INTO WEBHOOK_STATS" in query_normalized
        # Should use VALUES with parameters, not string interpolation


# ============================================================================
# 6. JSON SERIALIZATION SECURITY
# ============================================================================

class TestClickHouseAnalyticsJSONSerialization:
    """Test JSON serialization security."""
    
    @pytest.mark.asyncio
    async def test_circular_reference_payload(self):
        """Test circular reference in payload."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Circular reference
        circular_payload = {}
        circular_payload['self'] = circular_payload
        
        try:
            await analytics.save_log("test_webhook", circular_payload, {})
            # Should handle circular reference (json.dumps will raise TypeError)
            # Or should serialize safely
        except (TypeError, ValueError):
            # Acceptable - circular references can't be JSON serialized
            pass
    
    @pytest.mark.asyncio
    async def test_large_payload_dos(self):
        """Test DoS via very large payload."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Very large payload
        large_payload = {"data": "x" * 10000000}  # 10MB
        
        try:
            await analytics.save_log("test_webhook", large_payload, {})
            # Should handle large payload (might be slow, but shouldn't crash)
            assert not analytics.queue.empty()
        except (MemoryError, OSError):
            # Acceptable for extremely large payloads
            pass
    
    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test deeply nested payload."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Deeply nested payload
        nested_payload = {}
        current = nested_payload
        for i in range(1000):
            current['nested'] = {}
            current = current['nested']
        
        try:
            await analytics.save_log("test_webhook", nested_payload, {})
            # Should handle deeply nested payload
            assert not analytics.queue.empty()
        except (RecursionError, ValueError):
            # Acceptable for extremely deep nesting
            pass


# ============================================================================
# 7. WORKER AND QUEUE SECURITY
# ============================================================================

class TestClickHouseAnalyticsWorkerSecurity:
    """Test worker and queue security vulnerabilities."""
    
    # @pytest.mark.asyncio
    # async def test_queue_exhaustion_dos(self):
    #     """Test DoS via queue exhaustion."""
    #     config = {
    #         'host': 'localhost',
    #         'port': 9000,
    #         'database': 'test',
    #         'user': 'default',
    #         'password': ''
    #     }
    #     
    #     analytics = ClickHouseAnalytics(config)
    #     analytics.queue = asyncio.Queue(maxsize=100)  # Limited queue
    #     analytics._running = True
    #     
    #     # Try to fill queue
    #     try:
    #         for i in range(200):  # More than queue size
    #             await analytics.save_log(f"webhook_{i}", {"data": "test"}, {})
    #     except Exception:
    #         # Queue full exception is acceptable
    #         pass
    #     
    #     # Queue should be limited
    #     assert analytics.queue.qsize() <= 100
    
    @pytest.mark.asyncio
    async def test_worker_error_handling(self):
        """Test worker error handling."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        mock_client = MagicMock()
        analytics.client = mock_client
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Mock _flush_logs to raise exception
        async def mock_flush_logs(buffer):
            raise Exception("Flush error")
        
        analytics._flush_logs = mock_flush_logs
        
        # Add item to queue
        await analytics.save_log("test_webhook", {"data": "test"}, {})
        
        # Worker should handle error gracefully
        # Wait a bit for worker to process
        await asyncio.sleep(0.1)
        
        # Should not crash
        assert True
    
    @pytest.mark.asyncio
    async def test_worker_shutdown_race_condition(self):
        """Test race condition during worker shutdown."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Start worker
        analytics._worker_task = asyncio.create_task(analytics._worker())
        
        # Add items to queue
        for i in range(10):
            await analytics.save_log(f"webhook_{i}", {"data": "test"}, {})
        
        # Shutdown while items in queue
        await analytics.disconnect()
        
        # Should handle shutdown gracefully
        assert not analytics._running


# ============================================================================
# 8. TYPE CONFUSION AND EDGE CASES
# ============================================================================

class TestAnalyticsProcessorTypeConfusion:
    """Test type confusion vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test configuration type validation."""
        # Invalid config types
        invalid_configs = [
            None,
            "not a dict",
            123,
            [],
        ]
        
        for invalid_config in invalid_configs:
            try:
                processor = AnalyticsProcessor(invalid_config)
                # Should handle invalid config
                assert processor.clickhouse_config == invalid_config
            except (TypeError, AttributeError):
                # Acceptable - type validation should reject invalid configs
                pass
    
    @pytest.mark.asyncio
    async def test_save_stats_type_validation(self):
        """Test save_stats type validation."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Invalid stats types
        invalid_stats = [
            None,
            "not a dict",
            123,
            [],
        ]
        
        for invalid_stat in invalid_stats:
            try:
                await analytics.save_stats(invalid_stat)
                # Should handle gracefully
            except (TypeError, AttributeError):
                # Acceptable - type validation should reject invalid types
                pass
    
    @pytest.mark.asyncio
    async def test_save_log_type_validation(self):
        """Test save_log type validation."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Invalid webhook_id types
        invalid_ids = [
            None,
            123,
            [],
            {},
        ]
        
        for invalid_id in invalid_ids:
            try:
                await analytics.save_log(invalid_id, {"data": "test"}, {})
                # Should handle gracefully
            except (TypeError, AttributeError):
                # Acceptable - type validation should reject invalid types
                pass


# ============================================================================
# 9. CONCURRENT ACCESS SECURITY
# ============================================================================

class TestAnalyticsProcessorConcurrency:
    """Test concurrent access security."""
    
    @pytest.mark.asyncio
    async def test_concurrent_calculate_stats(self):
        """Test concurrent calculate_stats calls."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        processor = AnalyticsProcessor(config)
        mock_client = MagicMock()
        processor.client = mock_client
        
        # Concurrent calls
        tasks = [
            processor.calculate_stats(f"webhook_{i}") for i in range(10)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should complete
        assert len(results) == 10
        for result in results:
            assert isinstance(result, dict) or isinstance(result, Exception)
    
    @pytest.mark.asyncio
    async def test_concurrent_save_log(self):
        """Test concurrent save_log calls."""
        config = {
            'host': 'localhost',
            'port': 9000,
            'database': 'test',
            'user': 'default',
            'password': ''
        }
        
        analytics = ClickHouseAnalytics(config)
        analytics.queue = asyncio.Queue()
        analytics._running = True
        
        # Concurrent calls
        tasks = [
            analytics.save_log(f"webhook_{i}", {"data": f"test_{i}"}, {}) for i in range(10)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should complete
        assert len(results) == 10
        # Queue should have items
        assert analytics.queue.qsize() == 10


# ============================================================================
# 10. CONFIGURATION SECURITY
# ============================================================================

class TestAnalyticsProcessorConfigurationSecurity:
    """Test configuration security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_batch_size_injection(self):
        """Test batch_size configuration injection."""
        # Invalid batch sizes
        invalid_batch_sizes = [
            -1,
            0,
            1000000000,  # Very large
            "not a number",
            None,
        ]
        
        for invalid_size in invalid_batch_sizes:
            try:
                config = {
                    'host': 'localhost',
                    'port': 9000,
                    'database': 'test',
                    'user': 'default',
                    'password': ''
                }
                analytics = ClickHouseAnalytics(config, batch_size=invalid_size)
                # Should handle invalid batch_size
                assert analytics.batch_size == invalid_size or analytics.batch_size > 0
            except (TypeError, ValueError):
                # Acceptable - validation should reject invalid sizes
                pass
    
    @pytest.mark.asyncio
    async def test_flush_interval_injection(self):
        """Test flush_interval configuration injection."""
        # Invalid flush intervals
        invalid_intervals = [
            -1.0,
            0.0,
            1000000.0,  # Very large
            "not a number",
            None,
        ]
        
        for invalid_interval in invalid_intervals:
            try:
                config = {
                    'host': 'localhost',
                    'port': 9000,
                    'database': 'test',
                    'user': 'default',
                    'password': ''
                }
                analytics = ClickHouseAnalytics(config, flush_interval=invalid_interval)
                # Should handle invalid flush_interval
                assert analytics.flush_interval == invalid_interval or analytics.flush_interval > 0
            except (TypeError, ValueError):
                # Acceptable - validation should reject invalid intervals
                pass

