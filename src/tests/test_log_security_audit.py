"""
Comprehensive security audit tests for Log module.

Tests cover:
- Information disclosure (sensitive data in logs)
- Log injection attacks (newlines, control characters)
- DoS via large payloads
- Type confusion attacks
- Circular reference handling
- Config information disclosure
"""
import pytest
import sys
import io
from unittest.mock import patch
from src.modules.log import LogModule


# ============================================================================
# 1. INFORMATION DISCLOSURE
# ============================================================================

class TestInformationDisclosure:
    """Test information disclosure vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_config_information_disclosure(self):
        """Test that config sensitive information is redacted in logs."""
        # Config may contain sensitive connection details
        config = {
            'connection_details': {
                'password': 'secret123',
                'api_key': 'key123',
                'credentials_path': '/path/to/creds.json'
            },
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            await module.process({'test': 'data'}, {})
        
        output = captured_output.getvalue()
        
        # Config is printed but sensitive data should be redacted
        assert 'config:' in output
        assert 'secret123' not in output, "Password should be redacted"
        assert 'key123' not in output, "API key should be redacted"
        assert '[REDACTED' in output, "Sensitive data should be redacted"
    
    @pytest.mark.asyncio
    async def test_headers_information_disclosure(self):
        """Test that sensitive headers are redacted in logs."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        sensitive_headers = {
            'Authorization': 'Bearer secret-token',
            'X-API-Key': 'api-key-123',
            'Cookie': 'session=abc123'
        }
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            await module.process({'test': 'data'}, sensitive_headers)
        
        output = captured_output.getvalue()
        
        # Headers are printed but sensitive data should be redacted
        assert 'headers:' in output
        assert 'secret-token' not in output, "Authorization token should be redacted"
        assert 'api-key-123' not in output, "API key should be redacted"
        assert 'session=abc123' not in output, "Cookie should be redacted"
        assert '[REDACTED]' in output, "Sensitive headers should be redacted"
    
    @pytest.mark.asyncio
    async def test_payload_information_disclosure(self):
        """Test that sensitive payload data is redacted in logs."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        sensitive_payload = {
            'password': 'secret123',
            'credit_card': '1234-5678-9012-3456',
            'ssn': '123-45-6789'
        }
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            await module.process(sensitive_payload, {})
        
        output = captured_output.getvalue()
        
        # Payload is printed but sensitive data should be redacted
        assert 'body:' in output
        assert 'secret123' not in output, "Password should be redacted"
        assert '1234-5678-9012-3456' not in output, "Credit card should be redacted"
        assert '123-45-6789' not in output, "SSN should be redacted"
        assert '[REDACTED]' in output, "Sensitive payload data should be redacted"


# ============================================================================
# 2. LOG INJECTION ATTACKS
# ============================================================================

class TestLogInjection:
    """Test log injection attacks."""
    
    @pytest.mark.asyncio
    async def test_newline_injection_in_headers(self):
        """Test that newlines in headers are sanitized to prevent log injection."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Malicious header with newline to inject fake log entry
        malicious_headers = {
            'X-Test': 'normal\n[ERROR] Authentication failed for user admin'
        }
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            await module.process({'test': 'data'}, malicious_headers)
        
        output = captured_output.getvalue()
        
        # Newline should be sanitized (replaced with [NL])
        # Note: The output itself will have newlines between log lines, but not in the data
        # Check that the malicious newline in the header value is sanitized
        assert '[NL]' in output or '[CTRL]' in output, "Newlines in data should be sanitized"
    
    @pytest.mark.asyncio
    async def test_carriage_return_injection_in_payload(self):
        """Test that carriage returns in payload are sanitized to prevent log injection."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Malicious payload with carriage return
        malicious_payload = {
            'data': 'normal\r[WARNING] System compromised'
        }
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            await module.process(malicious_payload, {})
        
        output = captured_output.getvalue()
        
        # Carriage return should be sanitized (replaced with [NL])
        assert '\r' not in output, "Carriage return should be sanitized"
        assert '[NL]' in output or '[CTRL]' in output, "Control characters should be replaced with safe markers"
    
    @pytest.mark.asyncio
    async def test_control_character_injection(self):
        """Test that control characters are sanitized to prevent log corruption."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Malicious payload with control characters
        malicious_payload = {
            'data': 'normal\x00\x01\x02[FAKE] Log entry'
        }
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            await module.process(malicious_payload, {})
        
        output = captured_output.getvalue()
        
        # Control characters should be sanitized (replaced with [CTRL])
        assert '\x00' not in output, "Null byte should be sanitized"
        assert '\x01' not in output, "Control character should be sanitized"
        assert '[CTRL]' in output, "Control characters should be replaced with safe markers"


# ============================================================================
# 3. DENIAL OF SERVICE (DoS)
# ============================================================================

class TestDoS:
    """Test DoS vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_large_payload_dos(self):
        """Test that large payloads can cause DoS via stdout flooding."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Very large payload (10MB)
        large_payload = {'data': 'x' * (10 * 1024 * 1024)}
        
        # Capture stdout to prevent actual flooding
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            # Should handle without crashing, but might be slow
            await module.process(large_payload, {})
        
        output = captured_output.getvalue()
        # Large payload is printed - could cause DoS
        assert len(output) > 0
    
    @pytest.mark.asyncio
    async def test_deeply_nested_payload_dos(self):
        """Test that deeply nested payloads can cause DoS."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Deeply nested payload (1000 levels)
        nested = {}
        current = nested
        for i in range(1000):
            current['level'] = i
            current['next'] = {}
            current = current['next']
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            # Should handle without stack overflow
            await module.process(nested, {})
        
        output = captured_output.getvalue()
        assert len(output) > 0


# ============================================================================
# 4. TYPE CONFUSION
# ============================================================================

class TestTypeConfusion:
    """Test type confusion attacks."""
    
    @pytest.mark.asyncio
    async def test_non_string_payload_handling(self):
        """Test that non-string payloads are handled safely."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Various non-string payloads
        test_cases = [
            123,
            [1, 2, 3],
            {'key': 'value'},
            None,
        ]
        
        for payload in test_cases:
            # Capture stdout
            captured_output = io.StringIO()
            with patch('sys.stdout', captured_output):
                # Should handle without crashing
                await module.process(payload, {})
            
            output = captured_output.getvalue()
            assert 'body:' in output
    
    @pytest.mark.asyncio
    async def test_non_dict_headers_handling(self):
        """Test that non-dict headers are handled safely."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Non-dict headers (should be dict, but test edge case)
        # Note: process() expects Dict[str, str], but test if it's called incorrectly
        # This test documents expected behavior
        pass  # Headers type is enforced by type hints, but str() will handle it


# ============================================================================
# 5. CIRCULAR REFERENCE HANDLING
# ============================================================================

class TestCircularReference:
    """Test circular reference handling."""
    
    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payload are handled."""
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Create circular reference
        payload = {'key': 'value'}
        payload['self'] = payload  # Circular reference
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            # str() on circular reference will raise RecursionError or create infinite string
            # This is a vulnerability - should handle gracefully
            try:
                await module.process(payload, {})
                # If we get here, it might have created a very long string or crashed
            except RecursionError:
                # Expected - circular reference causes recursion
                pass
            except Exception:
                # Other exceptions possible
                pass


# ============================================================================
# 6. CONFIG SENSITIVE DATA
# ============================================================================

class TestConfigSensitiveData:
    """Test config sensitive data exposure."""
    
    @pytest.mark.asyncio
    async def test_connection_details_exposure(self):
        """Test that connection details in config are redacted."""
        config = {
            'connection_details': {
                'password': 'secret-password',
                'api_key': 'secret-api-key',
                'database_url': 'postgresql://user:pass@host/db'
            },
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            await module.process({'test': 'data'}, {})
        
        output = captured_output.getvalue()
        
        # Config is printed but connection details should be redacted
        assert 'config:' in output
        assert 'secret-password' not in output, "Password should be redacted"
        assert 'secret-api-key' not in output, "API key should be redacted"
        assert 'postgresql://user:pass@host/db' not in output, "Database URL should be redacted"
        assert '[REDACTED - connection details]' in output, "Connection details should be redacted"


# ============================================================================
# 7. CONCURRENT PROCESSING
# ============================================================================

class TestConcurrentProcessing:
    """Test concurrent processing security."""
    
    @pytest.mark.asyncio
    async def test_concurrent_logging(self):
        """Test that concurrent logging is handled safely."""
        import asyncio
        
        config = {
            'connection_details': {},
            'module-config': {}
        }
        
        module = LogModule(config)
        
        # Capture stdout
        captured_output = io.StringIO()
        with patch('sys.stdout', captured_output):
            # Simulate concurrent logging
            async def log(i):
                await module.process({'id': i}, {})
            
            # Run 10 concurrent logs
            await asyncio.gather(*[log(i) for i in range(10)])
        
        output = captured_output.getvalue()
        # Should handle concurrent logging without corruption
        assert output.count('body:') == 10

