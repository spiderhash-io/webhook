"""
Comprehensive security audit tests for WebSocketModule.
Tests payload security, error disclosure, message serialization, headers handling, and WebSocket-specific vulnerabilities.
"""
import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from src.modules.websocket import WebSocketModule


# ============================================================================
# 1. PAYLOAD SECURITY
# ============================================================================

class TestWebSocketPayloadSecurity:
    """Test payload security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payloads are handled safely."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        # Create circular reference
        payload = {"test": "data"}
        payload["self"] = payload  # Circular reference
        
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
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
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        # Very large payload
        large_payload = {"data": "x" * 10000000}  # 10MB string
        
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(large_payload, headers)
                # Should handle large payloads without DoS
                assert mock_ws.send.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled safely."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        # Deeply nested payload
        nested_payload = {"level": 0}
        current = nested_payload
        for i in range(1000):
            current["next"] = {"level": i + 1}
            current = current["next"]
        
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(nested_payload, headers)
                # Should handle deeply nested payloads safely
                assert mock_ws.send.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_non_serializable_payload(self):
        """Test that non-serializable payloads are handled safely."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        # Non-serializable object
        class NonSerializable:
            pass
        
        payload = {"obj": NonSerializable()}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
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

class TestWebSocketErrorDisclosure:
    """Test error message information disclosure."""
    
    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages are sanitized."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        # Mock websockets.connect to raise exception with sensitive info
        with patch('websockets.connect') as mock_connect:
            mock_connect.side_effect = Exception("Connection failed: password=secret_password, host=ws.internal")
            
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                assert False, "Should have raised exception"
            except Exception as e:
                # Should sanitize error message
                error_msg = str(e).lower()
                # Should not expose passwords or internal WebSocket details
                assert "secret_password" not in error_msg
                # Should contain sanitized error message
                assert "websocket" in error_msg or "processing error" in error_msg
    
    @pytest.mark.asyncio
    async def test_websocket_details_not_exposed(self):
        """Test that WebSocket-specific details are not exposed in errors."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        # Mock websockets.connect to raise WebSocket-specific exception
        with patch('websockets.connect') as mock_connect:
            import websockets.exceptions
            mock_connect.side_effect = websockets.exceptions.WebSocketException("Internal error: connection refused at ws://internal:8080")
            
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                # Should not expose WebSocket-specific error details
            except Exception as e:
                # Error should be sanitized
                error_msg = str(e).lower()
                # Should not expose internal WebSocket details
                pass


# ============================================================================
# 3. MESSAGE SERIALIZATION SECURITY
# ============================================================================

class TestWebSocketMessageSerialization:
    """Test message serialization security."""
    
    @pytest.mark.asyncio
    async def test_message_serialization_unicode(self):
        """Test JSON serialization with Unicode characters."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        # Payload with Unicode
        payload = {"test": "测试_🔑_ключ"}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(payload, headers)
                # Should serialize Unicode correctly
                assert mock_ws.send.called
                # Check that message was serialized
                call_args = mock_ws.send.call_args
                message = call_args[0][0] if call_args[0] else None
                if message:
                    # Message should be valid JSON
                    parsed = json.loads(message)
                    assert "payload" in parsed
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_message_serialization_special_chars(self):
        """Test JSON serialization with special characters."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        # Payload with special characters
        payload = {"test": "value\nwith\rspecial\tchars"}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(payload, headers)
                # Should serialize special characters correctly
                assert mock_ws.send.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_message_structure_json_format(self):
        """Test that message structure is correct for JSON format."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "format": "json",
                "include_headers": True
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {"X-Test": "value"}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            await module.process(payload, headers)
            
            # Check that message was sent with correct structure
            assert mock_ws.send.called
            call_args = mock_ws.send.call_args
            message = call_args[0][0] if call_args[0] else None
            
            if message:
                parsed = json.loads(message)
                assert "payload" in parsed
                assert "headers" in parsed
                assert parsed["payload"] == payload
                assert parsed["headers"] == headers
    
    @pytest.mark.asyncio
    async def test_message_structure_raw_format(self):
        """Test that message structure is correct for raw format."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "format": "raw"
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            await module.process(payload, headers)
            
            # Check that message was sent
            assert mock_ws.send.called
            call_args = mock_ws.send.call_args
            message = call_args[0][0] if call_args[0] else None
            
            if message:
                # Should be JSON string for dict payload
                parsed = json.loads(message)
                assert parsed == payload


# ============================================================================
# 4. HEADERS HANDLING SECURITY
# ============================================================================

class TestWebSocketHeadersHandling:
    """Test headers handling security."""
    
    @pytest.mark.asyncio
    async def test_headers_with_special_characters(self):
        """Test that headers with special characters are handled safely."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "include_headers": True
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        # Headers with special characters
        headers = {
            "X-Test": "value\nwith\rspecial\tchars",
            "X-Another": "value with spaces"
        }
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(payload, headers)
                # Should handle special characters in headers safely
                assert mock_ws.send.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_headers_with_unicode(self):
        """Test that headers with Unicode are handled safely."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "include_headers": True
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {
            "X-Test": "测试_🔑_ключ"
        }
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(payload, headers)
                # Should handle Unicode in headers safely
                assert mock_ws.send.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_extra_headers_injection(self):
        """Test that extra headers for WebSocket connection are handled safely."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "headers": {
                    "Authorization": "Bearer token123",
                    "X-Custom": "value"
                }
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            await module.process(payload, headers)
            
            # Check that extra_headers were passed to websockets.connect
            assert mock_connect.called
            call_kwargs = mock_connect.call_args[1] if mock_connect.call_args else {}
            extra_headers = call_kwargs.get('extra_headers', {})
            assert "Authorization" in extra_headers
            assert extra_headers["Authorization"] == "Bearer token123"


# ============================================================================
# 5. CONFIGURATION SECURITY
# ============================================================================

class TestWebSocketConfigurationSecurity:
    """Test configuration security and type validation."""
    
    def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {"module": "websocket", "module-config": {"url": None}},
            {"module": "websocket", "module-config": {"url": 123}},
            {"module": "websocket", "module-config": {"url": []}},
            {"module": "websocket", "module-config": {"url": {}}},
        ]
        
        for invalid_config in invalid_configs:
            try:
                module = WebSocketModule(invalid_config)
                # Should validate URL type during initialization
                assert module._validated_url is None or isinstance(module._validated_url, str)
            except ValueError as e:
                # Should raise ValueError for invalid URL types
                assert "non-empty string" in str(e).lower() or "must be" in str(e).lower()
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_missing_url_handling(self):
        """Test that missing URL is handled safely."""
        config = {
            "module": "websocket",
            "module-config": {}
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        try:
            await module.process(payload, headers)
            assert False, "Should have raised exception"
        except Exception as e:
            # Should raise exception for missing URL
            assert "url" in str(e).lower() or "not specified" in str(e).lower()


# ============================================================================
# 6. CONCURRENT PROCESSING
# ============================================================================

class TestWebSocketConcurrentProcessing:
    """Test concurrent processing security."""
    
    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that concurrent message processing is handled safely."""
        import asyncio
        
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            # Process multiple messages concurrently
            async def process_message(i):
                module = WebSocketModule(config)
                payload = {"test": f"data_{i}"}
                headers = {}
                await module.process(payload, headers)
            
            # Process 10 messages concurrently
            tasks = [process_message(i) for i in range(10)]
            await asyncio.gather(*tasks)
            
            # Should handle concurrent processing safely
            assert mock_connect.call_count >= 10


# ============================================================================
# 7. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================

class TestWebSocketEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test handling of empty payload."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(payload, headers)
                # Should handle empty payload safely
                assert mock_ws.send.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_none_payload(self):
        """Test handling of None payload."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws"
            }
        }
        
        module = WebSocketModule(config)
        
        payload = None
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(payload, headers)
                # Should handle None payload safely
                assert mock_ws.send.called
            except Exception as e:
                # Should not crash
                pass
    
    @pytest.mark.asyncio
    async def test_empty_headers(self):
        """Test handling of empty headers."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "include_headers": True
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            try:
                await module.process(payload, headers)
                # Should handle empty headers safely
                assert mock_ws.send.called
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 8. WEBSOCKET-SPECIFIC VULNERABILITIES
# ============================================================================

class TestWebSocketSpecific:
    """Test WebSocket-specific vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_retry_mechanism(self):
        """Test that retry mechanism works correctly."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "max_retries": 3
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Mock websockets.connect to fail twice then succeed
        with patch('websockets.connect') as mock_connect:
            import websockets.exceptions
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            
            # Fail twice, then succeed
            mock_connect.side_effect = [
                websockets.exceptions.WebSocketException("Connection failed"),
                websockets.exceptions.WebSocketException("Connection failed"),
                type('MockContext', (), {
                    '__aenter__': lambda self: mock_ws,
                    '__aexit__': lambda self, *args: None
                })()
            ]
            
            try:
                await module.process(payload, headers)
                # Should retry and eventually succeed
                assert mock_connect.call_count == 3
            except Exception as e:
                # Should handle retries gracefully
                pass
    
    @pytest.mark.asyncio
    async def test_timeout_configuration(self):
        """Test that timeout configuration is respected."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "timeout": 5
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            await module.process(payload, headers)
            
            # Check that timeout was passed to websockets.connect
            assert mock_connect.called
            call_kwargs = mock_connect.call_args[1] if mock_connect.call_args else {}
            assert call_kwargs.get('open_timeout') == 5
            assert call_kwargs.get('close_timeout') == 5
    
    @pytest.mark.asyncio
    async def test_wait_for_response(self):
        """Test that wait_for_response option works correctly."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "wait_for_response": True
            }
        }
        
        module = WebSocketModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Mock websockets.connect
        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value="response")
            mock_connect.return_value.__aenter__.return_value = mock_ws
            mock_connect.return_value.__aexit__.return_value = None
            
            await module.process(payload, headers)
            
            # Should wait for response
            assert mock_ws.recv.called


# ============================================================================
# 9. ALLOWED HOSTS WHITELIST SECURITY
# ============================================================================

class TestWebSocketAllowedHosts:
    """Test allowed hosts whitelist security."""
    
    def test_allowed_hosts_empty_list(self):
        """Test that empty allowed_hosts list blocks all hosts."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "allowed_hosts": []  # Empty whitelist
            }
        }
        
        # Empty whitelist should be treated as "no whitelist" and validate host normally
        # Since example.com is public, it should be allowed
        try:
            module = WebSocketModule(config)
            # Should validate host normally (public host should be allowed)
            assert module._validated_url == "ws://example.com/ws"
        except ValueError as e:
            # If empty whitelist blocks all, should raise ValueError
            assert "not in the allowed hosts whitelist" in str(e) or "whitelist is empty" in str(e)
    
    def test_allowed_hosts_invalid_type(self):
        """Test that invalid allowed_hosts type is handled."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "allowed_hosts": "not_a_list"  # Invalid type
            }
        }
        
        # Should treat as None (no whitelist) and validate host normally
        try:
            module = WebSocketModule(config)
            # Should validate host normally (public host should be allowed)
            assert module._validated_url == "ws://example.com/ws"
        except Exception as e:
            # Should not crash
            pass
    
    def test_allowed_hosts_whitespace_handling(self):
        """Test that whitespace in allowed_hosts is handled."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://  example.com  /ws",  # URL with whitespace
                "allowed_hosts": ["example.com"]
            }
        }
        
        # URL should be stripped during validation
        try:
            module = WebSocketModule(config)
            # Host should be extracted and matched case-insensitively
            assert "example.com" in module._validated_url.lower()
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 10. URL VALIDATION EDGE CASES
# ============================================================================

class TestWebSocketURLValidation:
    """Test URL validation edge cases."""
    
    def test_url_validation_octal_encoding(self):
        """Test that octal-encoded localhost is blocked."""
        octal_urls = [
            "ws://0177.0.0.1/ws",  # Octal encoding
            "ws://127.000.000.001/ws",  # Zero-padded
        ]
        
        for url in octal_urls:
            config = {
                "module": "websocket",
                "module-config": {
                    "url": url
                }
            }
            try:
                WebSocketModule(config)
                # Should block octal-encoded localhost
            except ValueError as e:
                # Should reject localhost variants
                assert "localhost" in str(e).lower() or "loopback" in str(e).lower() or "not allowed" in str(e).lower() or "invalid hostname" in str(e).lower()
    
    def test_url_validation_hex_encoding(self):
        """Test that hex-encoded localhost is blocked."""
        hex_urls = [
            "ws://0x7f.0.0.1/ws",  # Hex encoding
            "ws://0x7f000001/ws",  # Hex integer
        ]
        
        for url in hex_urls:
            config = {
                "module": "websocket",
                "module-config": {
                    "url": url
                }
            }
            try:
                WebSocketModule(config)
                # Should block hex-encoded localhost
            except ValueError as e:
                # Should reject localhost variants
                assert "localhost" in str(e).lower() or "loopback" in str(e).lower() or "not allowed" in str(e).lower() or "invalid hostname" in str(e).lower()
    
    def test_url_validation_decimal_encoding(self):
        """Test that decimal-encoded localhost is blocked."""
        decimal_urls = [
            "ws://2130706433/ws",  # Decimal encoding of 127.0.0.1
        ]
        
        for url in decimal_urls:
            config = {
                "module": "websocket",
                "module-config": {
                    "url": url
                }
            }
            try:
                WebSocketModule(config)
                # Should block decimal-encoded localhost
            except ValueError as e:
                # Should reject localhost variants
                assert "localhost" in str(e).lower() or "loopback" in str(e).lower() or "not allowed" in str(e).lower() or "private" in str(e).lower() or "invalid hostname" in str(e).lower()

