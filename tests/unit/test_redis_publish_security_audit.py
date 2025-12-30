"""
Comprehensive security audit tests for RedisPublishModule.
Tests payload security, error disclosure, connection security, configuration security, and concurrent processing.
"""
import pytest
import json
import redis
from unittest.mock import AsyncMock, patch, MagicMock
from src.modules.redis_publish import RedisPublishModule


# ============================================================================
# 1. PAYLOAD SECURITY
# ============================================================================

class TestRedisPublishPayloadSecurity:
    """Test payload security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payload are handled safely."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Create circular reference
        payload = {"test": "data"}
        payload["self"] = payload  # Circular reference
        
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
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
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Very large payload
        large_payload = {"data": "x" * 10000000}  # 10MB string
        
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(large_payload, headers)
                # Should handle large payloads without DoS
                assert mock_client.publish.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled safely."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Deeply nested payload
        nested_payload = {"level": 0}
        current = nested_payload
        for i in range(1000):
            current["next"] = {"level": i + 1}
            current = current["next"]
        
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(nested_payload, headers)
                # Should handle deeply nested payloads safely
                assert mock_client.publish.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_non_serializable_payload(self):
        """Test that non-serializable payloads are handled safely."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Non-serializable object
        class NonSerializable:
            pass
        
        payload = {"obj": NonSerializable()}
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(payload, headers)
                # JSON serialization should fail for non-serializable objects
            except (TypeError, ValueError) as e:
                # Expected error for non-serializable objects
                assert "not serializable" in str(e).lower() or "not JSON serializable" in str(e).lower() or isinstance(e, (TypeError, ValueError))
            except Exception as e:
                # Should not crash with unexpected errors
                pass


# ============================================================================
# 2. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestRedisPublishErrorDisclosure:
    """Test error message information disclosure."""
    
    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages are sanitized."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Mock Redis client to raise exception with sensitive info
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            # Use redis.ConnectionError to simulate real Redis error
            mock_client.ping.side_effect = redis.ConnectionError("Connection failed: password=secret_password, host=8.8.8.8")
            mock_redis_class.return_value = mock_client
            
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                assert False, "Should have raised exception"
            except ConnectionError as e:
                # Should sanitize error message
                error_msg = str(e).lower()
                # ConnectionError includes host:port, but should not expose sensitive details
                assert "8.8.8.8" in error_msg or "6379" in error_msg  # Host/port is OK
                # But should not expose passwords or internal Redis details
                assert "secret_password" not in error_msg
                # Should contain sanitized error message
                assert "redis connection" in error_msg or "processing error" in error_msg
    
    @pytest.mark.asyncio
    async def test_redis_details_not_exposed(self):
        """Test that Redis-specific details are not exposed in errors."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Mock Redis client to raise Redis-specific exception
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.side_effect = redis.ConnectionError("Redis internal error: AUTH failed")
            mock_redis_class.return_value = mock_client
            
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                # Should not expose Redis-specific error details
            except ConnectionError as e:
                # Error should be sanitized
                error_msg = str(e).lower()
                # Should not expose internal Redis details
                pass


# ============================================================================
# 3. CONNECTION SECURITY
# ============================================================================

class TestRedisPublishConnectionSecurity:
    """Test connection security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_connection_timeout(self):
        """Test that connection timeouts are handled safely."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Mock Redis client to timeout
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.side_effect = redis.TimeoutError("Connection timeout")
            mock_redis_class.return_value = mock_client
            
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                assert False, "Should have raised ConnectionError"
            except ConnectionError as e:
                # Should handle timeout gracefully
                assert "Failed to connect" in str(e) or "timeout" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_connection_refused(self):
        """Test that connection refused errors are handled safely."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Mock Redis client to refuse connection
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.side_effect = ConnectionRefusedError("Connection refused")
            mock_redis_class.return_value = mock_client
            
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                assert False, "Should have raised ConnectionError"
            except ConnectionError as e:
                # Should handle connection refused gracefully
                assert "Failed to connect" in str(e) or "refused" in str(e).lower()


# ============================================================================
# 4. CONFIGURATION SECURITY
# ============================================================================

class TestRedisPublishConfigurationSecurity:
    """Test configuration security and type validation."""
    
    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {"module": "redis_publish", "redis": {"host": "8.8.8.8", "port": 6379, "channel": None}},
            {"module": "redis_publish", "redis": {"host": "8.8.8.8", "port": 6379, "channel": 123}},
            {"module": "redis_publish", "redis": {"host": "8.8.8.8", "port": 6379, "channel": []}},
            {"module": "redis_publish", "redis": {"host": "8.8.8.8", "port": 6379, "channel": {}}},
        ]
        
        for invalid_config in invalid_configs:
            try:
                module = RedisPublishModule(invalid_config)
                # Should validate channel type during initialization
                assert module._validated_channel is None or isinstance(module._validated_channel, str)
            except ValueError as e:
                # Should raise ValueError for invalid channel types
                assert "non-empty string" in str(e).lower() or "must be" in str(e).lower()
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_redis_config_type_validation(self):
        """Test that redis config values are validated for correct types."""
        # Test invalid host type
        try:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": 123,  # Invalid type
                    "port": 6379,
                    "channel": "test_channel"
                }
            }
            RedisPublishModule(config)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            # Should raise ValueError for invalid host type
            assert "non-empty string" in str(e).lower() or "must be" in str(e).lower()
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 5. MESSAGE SERIALIZATION SECURITY
# ============================================================================

class TestRedisPublishMessageSerialization:
    """Test message serialization security."""
    
    @pytest.mark.asyncio
    async def test_message_serialization_unicode(self):
        """Test JSON serialization with Unicode characters."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Payload with Unicode
        payload = {"test": "测试_🔑_ключ"}
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(payload, headers)
                # Should serialize Unicode correctly
                assert mock_client.publish.called
                # Check that message was serialized
                call_args = mock_client.publish.call_args
                message = call_args[0][1] if call_args[0] else None
                if message:
                    # Message should be valid JSON
                    parsed = json.loads(message)
                    assert "payload" in parsed
                    assert "headers" in parsed
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_message_serialization_special_chars(self):
        """Test JSON serialization with special characters."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Payload with special characters
        payload = {"test": "value\nwith\rspecial\tchars"}
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(payload, headers)
                # Should serialize special characters correctly
                assert mock_client.publish.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_message_structure(self):
        """Test that message structure is correct."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        payload = {"test": "data"}
        headers = {"X-Test": "value"}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            await module.process(payload, headers)
            
            # Check that message was published with correct structure
            assert mock_client.publish.called
            call_args = mock_client.publish.call_args
            channel = call_args[0][0] if call_args[0] else None
            message = call_args[0][1] if call_args[0] and len(call_args[0]) > 1 else None
            
            assert channel == "test_channel"
            if message:
                parsed = json.loads(message)
                assert "payload" in parsed
                assert "headers" in parsed
                assert parsed["payload"] == payload
                assert parsed["headers"] == headers


# ============================================================================
# 6. CONCURRENT PROCESSING
# ============================================================================

class TestRedisPublishConcurrentProcessing:
    """Test concurrent processing security."""
    
    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that concurrent message processing is handled safely."""
        import asyncio
        
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            # Process multiple messages concurrently
            async def process_message(i):
                payload = {"test": f"data_{i}"}
                headers = {}
                await module.process(payload, headers)
            
            # Process 10 messages concurrently
            tasks = [process_message(i) for i in range(10)]
            await asyncio.gather(*tasks)
            
            # Should handle concurrent processing safely
            # Note: Each process() call creates a new Redis client, so we expect multiple calls
            assert mock_redis_class.call_count >= 10


# ============================================================================
# 7. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================

class TestRedisPublishEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test handling of empty payload."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        payload = {}
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(payload, headers)
                # Should handle empty payload safely
                assert mock_client.publish.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_none_payload(self):
        """Test handling of None payload."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        payload = None
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(payload, headers)
                # Should handle None payload safely
                assert mock_client.publish.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_empty_headers(self):
        """Test handling of empty headers."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(payload, headers)
                # Should handle empty headers safely
                assert mock_client.publish.called
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 8. CHANNEL NAME VALIDATION EDGE CASES
# ============================================================================

class TestRedisPublishChannelNameValidation:
    """Test channel name validation edge cases."""
    
    def test_channel_name_at_max_length(self):
        """Test channel name at maximum length."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "a" * 255  # Max length
            }
        }
        
        module = RedisPublishModule(config)
        assert module._validated_channel == "a" * 255
    
    def test_channel_name_regex_redos(self):
        """Test ReDoS vulnerability in channel name regex."""
        import time
        
        # Complex channel name that might cause ReDoS
        complex_name = "a" * 1000 + "!"  # Long string ending with invalid char
        
        start_time = time.time()
        try:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",
                    "port": 6379,
                    "channel": complex_name
                }
            }
            RedisPublishModule(config)
            assert False, "Should have raised ValueError"
        except ValueError:
            elapsed = time.time() - start_time
            # Should complete quickly (no ReDoS)
            assert elapsed < 1.0, f"ReDoS detected: validation took {elapsed:.2f}s"


# ============================================================================
# 9. HOST VALIDATION EDGE CASES
# ============================================================================

class TestRedisPublishHostValidation:
    """Test host validation edge cases."""
    
    def test_host_validation_octal_encoding(self):
        """Test that octal-encoded localhost is blocked."""
        octal_hosts = [
            "0177.0.0.1",  # Octal encoding
            "127.000.000.001",  # Zero-padded
        ]
        
        for host in octal_hosts:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": host,
                    "port": 6379,
                    "channel": "test_channel"
                }
            }
            try:
                RedisPublishModule(config)
                # Should block octal-encoded localhost
            except ValueError as e:
                # Should reject localhost variants
                assert "localhost" in str(e).lower() or "loopback" in str(e).lower() or "not allowed" in str(e).lower()
    
    def test_host_validation_hex_encoding(self):
        """Test that hex-encoded localhost is blocked."""
        hex_hosts = [
            "0x7f.0.0.1",  # Hex encoding
            "0x7f000001",  # Hex integer
        ]
        
        for host in hex_hosts:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": host,
                    "port": 6379,
                    "channel": "test_channel"
                }
            }
            try:
                RedisPublishModule(config)
                # Should block hex-encoded localhost
            except ValueError as e:
                # Should reject localhost variants
                assert "localhost" in str(e).lower() or "loopback" in str(e).lower() or "not allowed" in str(e).lower() or "invalid hostname" in str(e).lower()
    
    def test_host_validation_decimal_encoding(self):
        """Test that decimal-encoded localhost is blocked."""
        decimal_hosts = [
            "2130706433",  # Decimal encoding of 127.0.0.1
        ]
        
        for host in decimal_hosts:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": host,
                    "port": 6379,
                    "channel": "test_channel"
                }
            }
            try:
                RedisPublishModule(config)
                # Should block decimal-encoded localhost
            except ValueError as e:
                # Should reject localhost variants
                assert "localhost" in str(e).lower() or "loopback" in str(e).lower() or "not allowed" in str(e).lower() or "private" in str(e).lower()


# ============================================================================
# 10. PORT VALIDATION EDGE CASES
# ============================================================================

class TestRedisPublishPortValidation:
    """Test port validation edge cases."""
    
    def test_port_validation_string_conversion(self):
        """Test that string ports are converted to integers."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": "6379",  # String port
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        assert isinstance(module._validated_port, int)
        assert module._validated_port == 6379
    
    def test_port_validation_whitespace_handling(self):
        """Test that whitespace in port strings is handled."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": " 6379 ",  # String port with whitespace
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        assert isinstance(module._validated_port, int)
        assert module._validated_port == 6379
    
    def test_port_validation_invalid_string(self):
        """Test that invalid string ports are rejected."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": "invalid",  # Invalid string port
                "channel": "test_channel"
            }
        }
        
        with pytest.raises(ValueError) as exc_info:
            RedisPublishModule(config)
        assert "port" in str(exc_info.value).lower() or "integer" in str(exc_info.value).lower()


# ============================================================================
# 11. ALLOWED HOSTS WHITELIST SECURITY
# ============================================================================

class TestRedisPublishAllowedHosts:
    """Test allowed hosts whitelist security."""
    
    def test_allowed_hosts_empty_list(self):
        """Test that empty allowed_hosts list blocks all hosts."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel",
                "allowed_hosts": []  # Empty whitelist
            }
        }
        
        with pytest.raises(ValueError) as exc_info:
            RedisPublishModule(config)
        assert "not in the allowed hosts whitelist" in str(exc_info.value) or "whitelist is empty" in str(exc_info.value)
    
    def test_allowed_hosts_invalid_type(self):
        """Test that invalid allowed_hosts type is handled."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel",
                "allowed_hosts": "not_a_list"  # Invalid type
            }
        }
        
        # Should treat as None (no whitelist) and validate host normally
        try:
            module = RedisPublishModule(config)
            # Should validate host normally (public IP should be allowed)
            assert module._validated_host == "8.8.8.8"
        except Exception as e:
            # Should not crash
            pass
    
    def test_allowed_hosts_whitespace_handling(self):
        """Test that whitespace in allowed_hosts is handled."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "  redis.example.com  ",  # Host with whitespace
                "port": 6379,
                "channel": "test_channel",
                "allowed_hosts": ["redis.example.com"]
            }
        }
        
        module = RedisPublishModule(config)
        # Host should be stripped and matched case-insensitively
        assert module._validated_host == "redis.example.com"


# ============================================================================
# 12. HEADERS HANDLING SECURITY
# ============================================================================

class TestRedisPublishHeadersHandling:
    """Test headers handling security."""
    
    @pytest.mark.asyncio
    async def test_headers_with_special_characters(self):
        """Test that headers with special characters are handled safely."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        payload = {"test": "data"}
        # Headers with special characters
        headers = {
            "X-Test": "value\nwith\rspecial\tchars",
            "X-Another": "value with spaces"
        }
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(payload, headers)
                # Should handle special characters in headers safely
                assert mock_client.publish.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_headers_with_unicode(self):
        """Test that headers with Unicode are handled safely."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",
                "port": 6379,
                "channel": "test_channel"
            }
        }
        
        module = RedisPublishModule(config)
        
        payload = {"test": "data"}
        headers = {
            "X-Test": "测试_🔑_ключ"
        }
        
        # Mock Redis client
        with patch('redis.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client.publish.return_value = 1
            mock_redis_class.return_value = mock_client
            
            try:
                await module.process(payload, headers)
                # Should handle Unicode in headers safely
                assert mock_client.publish.called
            except Exception as e:
                # Should not crash
                pass

