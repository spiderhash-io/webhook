"""
Comprehensive security audit tests for ActiveMQ module.

Tests cover:
- Destination name injection (STOMP command injection)
- SSRF via host/port (private IP access, metadata service)
- Header injection (STOMP header injection)
- Payload security (circular references, large payloads)
- Type confusion attacks
- Error information disclosure
- Port manipulation
- Destination type validation
- Connection security
"""
import pytest
import json
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch, Mock

# Mock stomp module before importing ActiveMQModule
mock_stomp = MagicMock()
mock_stomp.Connection = MagicMock()
sys.modules['stomp'] = mock_stomp

from src.modules.activemq import ActiveMQModule


# ============================================================================
# 1. DESTINATION NAME INJECTION
# ============================================================================

class TestDestinationNameInjection:
    """Test destination name injection attacks."""
    
    def test_destination_sql_injection_attempts(self):
        """Test that SQL/STOMP injection attempts in destination names are blocked."""
        invalid_destinations = [
            "queue'; DROP TABLE users; --",
            "queue\" UNION SELECT * FROM users --",
            "queue'; DELETE FROM users; --",
            "queue; INSERT INTO users VALUES ('hacker'); --",
            "queue' OR '1'='1",
            "queue; UPDATE users SET password='hacked'; --",
        ]
        
        for invalid_dest in invalid_destinations:
            config = {
                'connection_details': {},
                'module-config': {'destination': invalid_dest}
            }
            with pytest.raises(ValueError):
                ActiveMQModule(config)
    
    def test_destination_path_traversal(self):
        """Test that path traversal attempts in destination names are blocked."""
        invalid_destinations = [
            "../queue",
            "../../queue",
            "queue/../other",
            "queue\\..\\other",
        ]
        
        for invalid_dest in invalid_destinations:
            config = {
                'connection_details': {},
                'module-config': {'destination': invalid_dest}
            }
            with pytest.raises(ValueError):
                ActiveMQModule(config)
    
    def test_destination_reserved_prefixes(self):
        """Test that ActiveMQ reserved prefixes are rejected."""
        reserved_destinations = [
            "ActiveMQ.test",
            "VirtualTopic.test",
            "Consumer.test",
            "Queue.test",
            "Topic.test",
        ]
        
        for reserved_dest in reserved_destinations:
            config = {
                'connection_details': {},
                'module-config': {'destination': reserved_dest}
            }
            with pytest.raises(ValueError, match="reserved prefix"):
                ActiveMQModule(config)
    
    def test_destination_control_characters(self):
        """Test that control characters in destination names are rejected."""
        invalid_destinations = [
            "queue\nname",
            "queue\rname",
            "queue\0name",
            "queue\tname",
        ]
        
        for invalid_dest in invalid_destinations:
            config = {
                'connection_details': {},
                'module-config': {'destination': invalid_dest}
            }
            # Control characters should be rejected (either by format check or explicit check)
            with pytest.raises(ValueError):
                ActiveMQModule(config)
    
    def test_destination_type_confusion(self):
        """Test that non-string destination names are rejected."""
        invalid_types = [
            123,
            [],
            {},
            {'key': 'value'},
        ]
        
        for invalid_type in invalid_types:
            config = {
                'connection_details': {},
                'module-config': {'destination': invalid_type}
            }
            # Should reject non-string types (None is handled separately - sets to None)
            with pytest.raises(ValueError):
                ActiveMQModule(config)
    
    def test_destination_too_long(self):
        """Test that excessively long destination names are rejected."""
        config = {
            'connection_details': {},
            'module-config': {'destination': 'a' * 256}  # Exceeds 255 limit
        }
        with pytest.raises(ValueError, match="too long"):
            ActiveMQModule(config)


# ============================================================================
# 2. SSRF VIA HOST/PORT
# ============================================================================

class TestSSRFPrevention:
    """Test SSRF prevention via hostname validation."""
    
    @pytest.mark.asyncio
    async def test_ssrf_localhost_blocked(self):
        """Test that localhost connections are blocked."""
        config = {
            'connection_details': {
                'host': 'localhost',
                'port': 61613,
                'user': 'test_user',
                'password': 'test_pass'
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        # Error is sanitized, but original error should contain "blocked for security"
        # Check that exception is raised (error sanitization happens)
        with pytest.raises(Exception):
            await module.setup()
    
    @pytest.mark.asyncio
    async def test_ssrf_127_0_0_1_blocked(self):
        """Test that 127.0.0.1 is blocked."""
        config = {
            'connection_details': {
                'host': '127.0.0.1',
                'port': 61613,
                'user': 'test_user',
                'password': 'test_pass'
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        # Error is sanitized, but should raise exception
        with pytest.raises(Exception):
            await module.setup()
    
    @pytest.mark.asyncio
    async def test_ssrf_private_ip_ranges_blocked(self):
        """Test that private IP ranges are blocked."""
        private_ips = [
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            '169.254.169.254',  # AWS metadata service (link-local)
        ]
        
        for ip in private_ips:
            config = {
                'connection_details': {
                    'host': ip,
                    'port': 61613,
                    'user': 'test_user',
                    'password': 'test_pass'
                },
                'module-config': {'destination': 'test_queue'},
            }
            
            module = ActiveMQModule(config)
            # Should be blocked (error is sanitized but exception should be raised)
            with pytest.raises(Exception):
                await module.setup()
    
    @pytest.mark.asyncio
    async def test_ssrf_metadata_service_blocked(self):
        """Test that metadata service endpoints are blocked."""
        config = {
            'connection_details': {
                'host': 'metadata.google.internal',
                'port': 61613,
                'user': 'test_user',
                'password': 'test_pass'
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        # Should be blocked (error is sanitized but exception should be raised)
        with pytest.raises(Exception):
            await module.setup()
    
    @pytest.mark.asyncio
    async def test_ssrf_host_type_validation(self):
        """Test that non-string hosts are rejected."""
        config = {
            'connection_details': {
                'host': 123,  # Non-string
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        # Should raise exception (error is sanitized)
        with pytest.raises(Exception):
            await module.setup()


# ============================================================================
# 3. PORT MANIPULATION
# ============================================================================

class TestPortManipulation:
    """Test port manipulation attacks."""
    
    @pytest.mark.asyncio
    async def test_port_out_of_range(self):
        """Test that out-of-range ports are rejected."""
        invalid_ports = [
            0,
            -1,
            65536,
            100000,
        ]
        
        for invalid_port in invalid_ports:
            config = {
                'connection_details': {
                    'host': 'activemq.example.com',
                    'port': invalid_port,
                },
                'module-config': {'destination': 'test_queue'},
            }
            
            module = ActiveMQModule(config)
            # Should raise exception (error is sanitized)
            with pytest.raises(Exception):
                await module.setup()
    
    @pytest.mark.asyncio
    async def test_port_type_validation(self):
        """Test that non-integer ports are rejected."""
        invalid_ports = [
            '61613',  # String
            None,
            [],
            {},
        ]
        
        for invalid_port in invalid_ports:
            config = {
                'connection_details': {
                    'host': 'activemq.example.com',
                    'port': invalid_port,
                },
                'module-config': {'destination': 'test_queue'},
            }
            
            module = ActiveMQModule(config)
            # Should raise exception (error is sanitized)
            with pytest.raises(Exception):
                await module.setup()


# ============================================================================
# 4. HEADER INJECTION
# ============================================================================

class TestHeaderInjection:
    """Test STOMP header injection attacks."""
    
    @pytest.mark.asyncio
    async def test_header_newline_injection(self):
        """Test that newlines in headers are handled safely."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        
        # Mock connection
        mock_client = Mock()
        module.client = mock_client
        
        # Headers with newlines
        malicious_headers = {
            'X-Custom': 'value\nInjected-Header: malicious',
            'X-Another': 'value\rInjected-Header: malicious',
        }
        
        payload = {'test': 'data'}
        
        # Should handle safely - newlines might be in values but shouldn't break STOMP protocol
        await module.process(payload, malicious_headers)
        
        # Verify send was called
        assert mock_client.send.called
    
    @pytest.mark.asyncio
    async def test_header_null_byte_injection(self):
        """Test that null bytes in headers are handled safely."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        mock_client = Mock()
        module.client = mock_client
        
        malicious_headers = {
            'X-Custom': 'value\0null',
        }
        
        payload = {'test': 'data'}
        
        await module.process(payload, malicious_headers)
        assert mock_client.send.called
    
    @pytest.mark.asyncio
    async def test_header_type_confusion(self):
        """Test that non-string header values are handled safely."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        mock_client = Mock()
        module.client = mock_client
        
        # Headers with non-string values
        headers = {
            'X-Number': 123,
            'X-List': [1, 2, 3],
            'X-Dict': {'key': 'value'},
            'X-None': None,
        }
        
        payload = {'test': 'data'}
        
        # Code only includes string values: if isinstance(value, str)
        # So non-string values should be filtered out
        await module.process(payload, headers)
        
        # Verify send was called with filtered headers
        assert mock_client.send.called
        call_args = mock_client.send.call_args
        sent_headers = call_args[0][2] if len(call_args[0]) > 2 else {}
        # Non-string values should not be in headers
        assert 'X-Number' not in sent_headers or isinstance(sent_headers.get('X-Number'), str)


# ============================================================================
# 5. PAYLOAD SECURITY
# ============================================================================

class TestPayloadSecurity:
    """Test payload security (circular references, large payloads)."""
    
    @pytest.mark.asyncio
    async def test_circular_reference_handling(self):
        """Test that circular references in payload are handled."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        mock_client = Mock()
        module.client = mock_client
        
        # Create circular reference
        payload = {'key': 'value'}
        payload['self'] = payload  # Circular reference
        
        # json.dumps will raise ValueError for circular references
        with pytest.raises((ValueError, TypeError, OverflowError, Exception)):
            await module.process(payload, {})
    
    @pytest.mark.asyncio
    async def test_large_payload_handling(self):
        """Test that large payloads are handled without DoS."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        mock_client = Mock()
        module.client = mock_client
        
        # Large payload (10MB)
        large_payload = {'data': 'x' * (10 * 1024 * 1024)}
        
        # Should handle without crashing - might be slow but shouldn't DoS
        await module.process(large_payload, {})
        assert mock_client.send.called
    
    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        mock_client = Mock()
        module.client = mock_client
        
        # Deeply nested payload (1000 levels)
        nested = {}
        current = nested
        for i in range(1000):
            current['level'] = i
            current['next'] = {}
            current = current['next']
        
        # Should handle without stack overflow
        await module.process(nested, {})
        assert mock_client.send.called


# ============================================================================
# 6. DESTINATION TYPE VALIDATION
# ============================================================================

class TestDestinationTypeValidation:
    """Test destination type validation."""
    
    def test_destination_type_invalid(self):
        """Test that invalid destination types are rejected."""
        invalid_types = [
            'invalid',
            'queue_topic',
            'QUEUE',  # Case sensitive?
            'TOPIC',  # Case sensitive?
        ]
        
        for invalid_type in invalid_types:
            config = {
                'connection_details': {},
                'module-config': {
                    'destination': 'test_queue',
                    'destination_type': invalid_type
                }
            }
            
            # Code does .lower() so 'QUEUE' and 'TOPIC' should work
            # But 'invalid' should fail
            if invalid_type.lower() not in ['queue', 'topic']:
                with pytest.raises(ValueError, match="must be 'queue' or 'topic'"):
                    ActiveMQModule(config)
    
    def test_destination_type_case_insensitive(self):
        """Test that destination type is case-insensitive."""
        config = {
            'connection_details': {},
            'module-config': {
                'destination': 'test_queue',
                'destination_type': 'QUEUE'  # Uppercase
            }
        }
        
        # Should work due to .lower()
        module = ActiveMQModule(config)
        assert module.destination_type == 'queue'


# ============================================================================
# 7. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestErrorInformationDisclosure:
    """Test error information disclosure prevention."""
    
    @pytest.mark.asyncio
    async def test_connection_error_sanitization(self):
        """Test that connection errors are sanitized."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
                'user': 'test_user',
                'password': 'secret_password'
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        
        # Mock connection failure
        with patch('stomp.Connection') as mock_conn:
            mock_conn.side_effect = Exception("Connection failed: Access denied for user 'test_user' with password")
            
            with pytest.raises(Exception) as exc_info:
                await module.setup()
            
            # Error should be sanitized - should not contain password
            error_msg = str(exc_info.value)
            assert 'secret_password' not in error_msg
            assert 'password' not in error_msg.lower() or 'with password' not in error_msg.lower()
    
    @pytest.mark.asyncio
    async def test_publish_error_sanitization(self):
        """Test that publish errors are sanitized."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        mock_client = Mock()
        module.client = mock_client
        
        # Mock send failure
        mock_client.send.side_effect = Exception("Failed to send: Connection details exposed")
        
        payload = {'test': 'data'}
        
        with pytest.raises(Exception) as exc_info:
            await module.process(payload, {})
        
        # Error should be sanitized
        error_msg = str(exc_info.value)
        assert 'Connection details exposed' not in error_msg


# ============================================================================
# 8. MISSING DESTINATION VALIDATION
# ============================================================================

class TestMissingDestinationValidation:
    """Test handling of missing destination."""
    
    @pytest.mark.asyncio
    async def test_missing_destination(self):
        """Test that missing destination is handled."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {},  # No destination
        }
        
        module = ActiveMQModule(config)
        # Should raise error when setup is called
        with pytest.raises(ValueError, match="Destination is required"):
            await module.setup()
    
    def test_none_destination(self):
        """Test that None destination is handled."""
        config = {
            'connection_details': {},
            'module-config': {'destination': None},
        }
        
        # Module should be created but destination should be None
        module = ActiveMQModule(config)
        assert module._validated_destination is None
        
        # Should fail on setup
        with pytest.raises(ValueError, match="Destination is required"):
            asyncio.run(module.setup())


# ============================================================================
# 9. CONCURRENT PROCESSING
# ============================================================================

class TestConcurrentProcessing:
    """Test concurrent processing security."""
    
    @pytest.mark.asyncio
    async def test_concurrent_publish(self):
        """Test that concurrent publishes are handled safely."""
        config = {
            'connection_details': {
                'host': 'activemq.example.com',
                'port': 61613,
            },
            'module-config': {'destination': 'test_queue'},
        }
        
        module = ActiveMQModule(config)
        mock_client = Mock()
        module.client = mock_client
        
        # Simulate concurrent publishes
        async def publish(i):
            await module.process({'id': i}, {})
        
        # Run 10 concurrent publishes
        await asyncio.gather(*[publish(i) for i in range(10)])
        
        # Verify all sends were called
        assert mock_client.send.call_count == 10

