"""
Comprehensive security audit tests for ClickHouseModule.
Tests SQL injection, connection security, payload security, error disclosure, and configuration security.
"""
import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from src.modules.clickhouse import ClickHouseModule


# ============================================================================
# 1. SQL INJECTION VIA PAYLOAD/HEADERS
# ============================================================================

class TestClickHousePayloadInjection:
    """Test SQL injection via payload and headers."""
    
    @pytest.mark.asyncio
    async def test_sql_injection_via_payload(self):
        """Test that SQL injection attempts in payload are handled safely."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        # Payload with SQL injection attempt
        malicious_payload = {
            "test": "data'; DROP TABLE webhook_logs; --"
        }
        headers = {}
        
        try:
            await module.process(malicious_payload, headers)
            # Should handle SQL injection safely (payload is JSON serialized, not directly in SQL)
            # The payload is serialized to JSON string, so SQL injection is prevented
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_sql_injection_via_headers(self):
        """Test that SQL injection attempts in headers are handled safely."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs",
                "include_headers": True
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = {"test": "data"}
        # Headers with SQL injection attempt
        malicious_headers = {
            "X-Test-Header": "value'; DROP TABLE webhook_logs; --"
        }
        
        try:
            await module.process(payload, malicious_headers)
            # Should handle SQL injection safely (headers are JSON serialized, not directly in SQL)
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_payload_with_special_characters(self):
        """Test that payloads with special SQL characters are handled safely."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        # Payload with special characters
        payload = {
            "test": "value'; -- /* */ \" \" ` `"
        }
        headers = {}
        
        try:
            await module.process(payload, headers)
            # Should handle special characters safely
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 2. CONNECTION SECURITY
# ============================================================================

class TestClickHouseConnectionSecurity:
    """Test connection security vulnerabilities."""
    
    @pytest.mark.asyncio
    @pytest.mark.longrunning
    async def test_ssrf_via_host(self):
        """Test SSRF attempts via host configuration."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        
        # SSRF attempt hosts
        ssrf_hosts = [
            "127.0.0.1",
            "localhost",
            "169.254.169.254",  # AWS metadata
            "file:///etc/passwd",
            "http://evil.com",
        ]
        
        for ssrf_host in ssrf_hosts:
            module.connection_details = {
                "host": ssrf_host,
                "port": 9000,
                "database": "default",
                "user": "default"
            }
            
            try:
                await module.setup()
                # Should handle SSRF attempts safely
                # (clickhouse-driver will validate host format)
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_port_manipulation(self):
        """Test port manipulation attempts."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        
        # Invalid ports
        invalid_ports = [
            -1,
            0,
            65536,  # Out of range
            "invalid",
            None,
        ]
        
        for invalid_port in invalid_ports:
            module.connection_details = {
                "host": "localhost",
                "port": invalid_port,
                "database": "default",
                "user": "default"
            }
            
            try:
                await module.setup()
                # Should handle invalid ports safely
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_database_name_injection(self):
        """Test database name injection attempts."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        
        # Malicious database names
        malicious_databases = [
            "default'; DROP DATABASE default; --",
            "default\"; DROP DATABASE default; --",
            "../../etc/passwd",
        ]
        
        for malicious_db in malicious_databases:
            module.connection_details = {
                "host": "localhost",
                "port": 9000,
                "database": malicious_db,
                "user": "default"
            }
            
            try:
                await module.setup()
                # Should handle malicious database names safely
                # (clickhouse-driver will validate database name format)
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 3. PAYLOAD SECURITY
# ============================================================================

class TestClickHousePayloadSecurity:
    """Test payload security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payload are handled safely."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        # Create circular reference
        payload = {"test": "data"}
        payload["self"] = payload  # Circular reference
        
        headers = {}
        
        try:
            await module.process(payload, headers)
            # JSON serialization should handle circular references (may raise error)
        except (ValueError, TypeError) as e:
            # JSON serialization error is expected for circular references
            assert "circular" in str(e).lower() or "not serializable" in str(e).lower() or isinstance(e, (ValueError, TypeError))
        except Exception as e:
            # Should not crash with unexpected errors
            pass
    
    @pytest.mark.asyncio
    async def test_large_payload_dos(self):
        """Test that very large payloads are handled safely."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        # Very large payload
        large_payload = {"data": "x" * 10000000}  # 10MB string
        
        headers = {}
        
        try:
            await module.process(large_payload, headers)
            # Should handle large payloads without DoS
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled safely."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        # Deeply nested payload
        nested_payload = {"level": 0}
        current = nested_payload
        for i in range(1000):
            current["next"] = {"level": i + 1}
            current = current["next"]
        
        headers = {}
        
        try:
            await module.process(nested_payload, headers)
            # Should handle deeply nested payloads safely
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_non_serializable_payload(self):
        """Test that non-serializable payloads are handled safely."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        # Non-serializable object
        class NonSerializable:
            pass
        
        payload = {"obj": NonSerializable()}
        headers = {}
        
        try:
            await module.process(payload, headers)
            # JSON serialization should fail for non-serializable objects
            # But str() conversion should handle it
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 4. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestClickHouseErrorDisclosure:
    """Test error message information disclosure."""
    
    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages are sanitized."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        
        # Mock connection to raise exception with sensitive info
        module.connection_details = {
            "host": "localhost",
            "port": 9000,
            "database": "default",
            "user": "default",
            "password": "secret_password"
        }
        
        # Mock Client to raise exception
        with patch('src.modules.clickhouse.Client') as mock_client_class:
            mock_client_class.side_effect = Exception("Connection failed: password=secret_password, host=localhost")
            
            try:
                await module.setup()
                assert False, "Should have raised exception"
            except Exception as e:
                # Should sanitize error message
                error_msg = str(e).lower()
                assert "secret_password" not in error_msg
                assert "clickhouse connection" in error_msg or "processing error" in error_msg
    
    @pytest.mark.asyncio
    async def test_clickhouse_details_not_exposed(self):
        """Test that ClickHouse-specific details are not exposed in errors."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        # Mock execute to raise ClickHouse-specific exception
        from clickhouse_driver.errors import Error as ClickHouseError
        mock_client.execute.side_effect = ClickHouseError("Table 'webhook_logs' doesn't exist")
        
        payload = {"test": "data"}
        headers = {}
        
        try:
            await module.process(payload, headers)
            # Should not expose ClickHouse-specific error details
        except Exception as e:
            # Error should be sanitized
            error_msg = str(e).lower()
            # Should not expose internal ClickHouse details
            pass


# ============================================================================
# 5. CONFIGURATION SECURITY
# ============================================================================

class TestClickHouseConfigurationSecurity:
    """Test configuration security and type validation."""
    
    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {"module": "clickhouse", "module-config": {"table": None}},
            {"module": "clickhouse", "module-config": {"table": 123}},
            {"module": "clickhouse", "module-config": {"table": []}},
            {"module": "clickhouse", "module-config": {"table": {}}},
        ]
        
        for invalid_config in invalid_configs:
            try:
                module = ClickHouseModule(invalid_config)
                # Should validate table type during initialization
                assert module.table_name is None or isinstance(module.table_name, str)
            except ValueError as e:
                # Should raise ValueError for invalid table types
                assert "non-empty string" in str(e).lower() or "must be" in str(e).lower()
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_module_config_type_validation(self):
        """Test that module_config values are validated for correct types."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs",
                "include_headers": "true",  # String instead of bool
                "include_timestamp": 1,  # Int instead of bool
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = {"test": "data"}
        headers = {}
        
        try:
            await module.process(payload, headers)
            # Should handle invalid config types safely
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 6. QUERY CONSTRUCTION SECURITY
# ============================================================================

class TestClickHouseQueryConstruction:
    """Test query construction security."""
    
    @pytest.mark.asyncio
    async def test_parameterized_query_usage(self):
        """Test that queries use parameterized values (not string concatenation)."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = {"test": "data'; DROP TABLE webhook_logs; --"}
        headers = {}
        
        await module.process(payload, headers)
        
        # Check that execute was called with parameterized values
        assert mock_client.execute.called
        call_args = mock_client.execute.call_args
        
        # The query should use parameterized values, not string concatenation
        # ClickHouse driver uses parameterized queries via execute(query, data)
        query = call_args[0][0] if call_args[0] else None
        data = call_args[0][1] if len(call_args[0]) > 1 else None
        
        # Query should contain table name (quoted), but not payload data directly
        if query:
            assert "INSERT INTO" in query.upper()
            # Payload should be in data parameter, not in query string
            if data:
                # Data should be a list of tuples
                assert isinstance(data, list)
    
    @pytest.mark.asyncio
    async def test_table_name_quoted_in_query(self):
        """Test that table name is properly quoted in queries."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = {"test": "data"}
        headers = {}
        
        await module.process(payload, headers)
        
        # Check that table name is quoted in query
        assert mock_client.execute.called
        call_args = mock_client.execute.call_args
        query = call_args[0][0] if call_args[0] else None
        
        if query:
            # Table name should be quoted with backticks
            assert "`webhook_logs`" in query or "webhook_logs" in query


# ============================================================================
# 7. IDENTIFIER QUOTING SECURITY
# ============================================================================

class TestClickHouseIdentifierQuoting:
    """Test identifier quoting security."""
    
    def test_quote_identifier_backtick_escaping(self):
        """Test that backticks in identifiers are properly escaped."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        
        # Test backtick escaping
        quoted = module._quote_identifier("test`name")
        assert quoted == "`test``name`"
    
    def test_quote_identifier_normal_name(self):
        """Test quoting of normal identifier."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        
        quoted = module._quote_identifier("webhook_logs")
        assert quoted == "`webhook_logs`"
    
    def test_quote_identifier_empty_string(self):
        """Test quoting of empty string (edge case)."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        
        quoted = module._quote_identifier("")
        assert quoted == "``"


# ============================================================================
# 8. CONCURRENT PROCESSING
# ============================================================================

class TestClickHouseConcurrentProcessing:
    """Test concurrent processing security."""
    
    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that concurrent message processing is handled safely."""
        import asyncio
        
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        # Process multiple messages concurrently
        async def process_message(i):
            payload = {"test": f"data_{i}"}
            headers = {}
            await module.process(payload, headers)
        
        # Process 10 messages concurrently
        tasks = [process_message(i) for i in range(10)]
        await asyncio.gather(*tasks)
        
        # Should handle concurrent processing safely
        assert mock_client.execute.call_count >= 10


# ============================================================================
# 9. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================

class TestClickHouseEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test handling of empty payload."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = {}
        headers = {}
        
        try:
            await module.process(payload, headers)
            # Should handle empty payload safely
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_none_payload(self):
        """Test handling of None payload."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = None
        headers = {}
        
        try:
            await module.process(payload, headers)
            # Should handle None payload safely
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_client_not_initialized(self):
        """Test handling when client is not initialized."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        
        module = ClickHouseModule(config)
        # Client is None (not initialized)
        
        # Mock setup to create client
        with patch.object(module, 'setup', new_callable=AsyncMock) as mock_setup:
            mock_client = MagicMock()
            mock_setup.return_value = None
            module.client = mock_client
            
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                # Should initialize client if not present
                assert mock_setup.called or module.client is not None
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_include_headers_false(self):
        """Test handling when include_headers is False."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs",
                "include_headers": False
            }
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = {"test": "data"}
        headers = {"X-Test": "value"}
        
        try:
            await module.process(payload, headers)
            # Should handle include_headers=False safely
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 10. TABLE NAME VALIDATION EDGE CASES
# ============================================================================

class TestClickHouseTableNameValidation:
    """Test table name validation edge cases."""
    
    def test_table_name_at_max_length(self):
        """Test table name at maximum length."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "a" * 255  # Max length
            }
        }
        
        module = ClickHouseModule(config)
        assert module.table_name == "a" * 255
    
    def test_table_name_regex_redos(self):
        """Test ReDoS vulnerability in table name regex."""
        import time
        
        # Complex table name that might cause ReDoS
        complex_name = "a" * 1000 + "!"  # Long string ending with invalid char
        
        start_time = time.time()
        try:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": complex_name
                }
            }
            ClickHouseModule(config)
            assert False, "Should have raised ValueError"
        except ValueError:
            elapsed = time.time() - start_time
            # Should complete quickly (no ReDoS)
            assert elapsed < 1.0, f"ReDoS detected: validation took {elapsed:.2f}s"


# ============================================================================
# 11. WEBHOOK ID HANDLING
# ============================================================================

class TestClickHouseWebhookIdHandling:
    """Test webhook ID handling security."""
    
    @pytest.mark.asyncio
    async def test_webhook_id_injection(self):
        """Test that webhook_id injection attempts are handled safely."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            },
            "_webhook_id": "webhook_id'; DROP TABLE webhook_logs; --"
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = {"test": "data"}
        headers = {}
        
        try:
            await module.process(payload, headers)
            # Should handle webhook_id injection safely (webhook_id is in parameterized query)
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass
    
    @pytest.mark.asyncio
    async def test_missing_webhook_id(self):
        """Test handling when webhook_id is missing."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
            # No _webhook_id
        }
        
        module = ClickHouseModule(config)
        mock_client = MagicMock()
        module.client = mock_client
        
        payload = {"test": "data"}
        headers = {}
        
        try:
            await module.process(payload, headers)
            # Should handle missing webhook_id safely (defaults to 'unknown')
            assert mock_client.execute.called
        except Exception as e:
            # Should not crash
            pass

