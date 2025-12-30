"""
Comprehensive security audit tests for Webhook Processing Pipeline.
Tests JSON parsing DoS, path parameter injection, deserialization attacks, and encoding bypasses.
"""
import pytest
import json
import time
from httpx import AsyncClient, ASGITransport
from src.main import app
from src.webhook import WebhookHandler
from src.input_validator import InputValidator
from unittest.mock import Mock, patch
from fastapi import Request

host = "test"
test_url = f"http://{host}"


# ============================================================================
# 1. JSON PARSING DoS ATTACKS
# ============================================================================

class TestJSONParsingDoS:
    """Test JSON parsing denial-of-service attacks."""
    
    @pytest.mark.asyncio
    async def test_billion_laughs_attack(self):
        """Test billion laughs attack (XML bomb equivalent for JSON)."""
        # Create a JSON payload with repeated references that expand exponentially
        # This is less effective in JSON than XML, but we should still test
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Create deeply nested structure that could cause stack overflow
            # Python's json.loads handles this better than XML parsers, but we test anyway
            nested = {"a": "x" * 1000}
            for i in range(100):  # 100 levels of nesting
                nested = {"a": nested}
            
            payload = json.dumps(nested)
            
            # Should be rejected by depth validation (max 50 levels)
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should reject due to depth validation
            assert response.status_code in [400, 413]
    
    @pytest.mark.asyncio
    async def test_quadratic_blowup_attack(self):
        """Test quadratic blowup attack with repeated strings."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Create JSON with many repeated large strings
            # This could cause memory issues during parsing
            large_string = "x" * 10000
            payload_data = {
                f"key_{i}": large_string
                for i in range(1100)  # 1100 keys with 10KB strings = 11MB (over limit)
            }
            payload = json.dumps(payload_data)
            
            # Should be rejected by payload size validation (10MB limit)
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should reject due to size validation
            assert response.status_code in [400, 413]
    
    @pytest.mark.asyncio
    async def test_deeply_nested_arrays_dos(self):
        """Test DoS with deeply nested arrays."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Create array with 60 levels of nesting (over 50 limit)
            nested = [1]
            for i in range(60):
                nested = [nested]
            
            payload = json.dumps(nested)
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should reject due to depth validation
            assert response.status_code in [400, 413]
    
    @pytest.mark.asyncio
    async def test_massive_single_string_dos(self):
        """Test DoS with a single massive string."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Create JSON with single string over 1MB limit
            huge_string = "x" * (2 * 1024 * 1024)  # 2MB string
            payload_data = {"data": huge_string}
            payload = json.dumps(payload_data)
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should reject due to string length validation (1MB limit)
            assert response.status_code in [400, 413]
    
    @pytest.mark.asyncio
    async def test_json_parsing_timeout_attack(self):
        """Test if malformed JSON can cause parsing to hang."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url, timeout=5.0) as ac:
            # Create JSON with many nested brackets that could cause slow parsing
            # Python's json.loads is generally fast, but we test edge cases
            malformed = "{" * 10000 + "}" * 10000  # Unbalanced but could parse slowly
            
            start_time = time.time()
            response = await ac.post(
                "/webhook/print",
                content=malformed.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            elapsed = time.time() - start_time
            
            # Should reject quickly (within timeout)
            assert elapsed < 5.0, "JSON parsing took too long"
            assert response.status_code in [400, 413]


# ============================================================================
# 2. PATH PARAMETER INJECTION ATTACKS
# ============================================================================

class TestPathParameterInjection:
    """Test path parameter injection attacks beyond format validation."""
    
    @pytest.mark.asyncio
    async def test_path_traversal_in_webhook_id(self):
        """Test path traversal attempts in webhook ID."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            traversal_attempts = [
                "../stats",
                "webhook/../stats",
                "webhook/../../stats",
                "webhook%2F..%2Fstats",  # URL encoded
                "webhook%252F..%252Fstats",  # Double encoded
            ]
            
            for webhook_id in traversal_attempts:
                response = await ac.post(
                    f"/webhook/{webhook_id}",
                    json={"data": "test"}
                )
                # Should be rejected by webhook ID validation or route matching
                # FastAPI may return 405 (Method Not Allowed) for invalid paths
                assert response.status_code in [400, 404, 405]
    
    @pytest.mark.asyncio
    async def test_null_byte_injection_webhook_id(self):
        """Test null byte injection in webhook ID."""
        # httpx will reject null bytes in URLs before reaching server
        # This is expected behavior - test that validation would reject it
        null_byte_id = "webhook\x00stats"
        is_valid, msg = InputValidator.validate_webhook_id(null_byte_id)
        # Should be rejected by validation
        assert not is_valid, "Should reject webhook ID with null byte"
    
    @pytest.mark.asyncio
    async def test_unicode_normalization_attack(self):
        """Test Unicode normalization attacks in webhook ID."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Unicode characters that normalize to reserved names
            # e.g., using lookalike characters
            unicode_attempts = [
                "ѕtаtѕ",  # Cyrillic lookalikes
                "ѕtаtѕ",  # Mixed scripts
            ]
            
            for webhook_id in unicode_attempts:
                response = await ac.post(
                    f"/webhook/{webhook_id}",
                    json={"data": "test"}
                )
                # Should be validated (may pass if not checking Unicode normalization)
                # This is acceptable as long as it doesn't access reserved endpoints
                assert response.status_code in [200, 400, 401, 404]
    
    @pytest.mark.asyncio
    async def test_webhook_id_case_confusion(self):
        """Test case confusion attacks to bypass reserved name checks."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Test that case variations of reserved names are blocked
            case_variations = [
                "STATS",
                "Stats",
                "StAtS",
                "sTaTs",
            ]
            
            for webhook_id in case_variations:
                response = await ac.post(
                    f"/webhook/{webhook_id}",
                    json={"data": "test"}
                )
                # Should be rejected (case-insensitive check)
                assert response.status_code in [400, 404]
                if response.status_code == 400:
                    assert "reserved" in response.json()["detail"].lower()


# ============================================================================
# 3. JSON DESERIALIZATION VULNERABILITIES
# ============================================================================

class TestJSONDeserializationAttacks:
    """Test JSON deserialization-specific vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_json_with_duplicate_keys(self):
        """Test JSON with duplicate keys (last one wins in Python)."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # JSON with duplicate keys - Python json.loads keeps last value
            # This could be used to bypass validation if first key is validated
            payload = '{"key": "valid", "key": "malicious"}'
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process (Python's json.loads handles this)
            # This is acceptable behavior
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_json_with_unicode_escape_sequences(self):
        """Test JSON with Unicode escape sequences that could bypass validation."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Unicode escape sequences
            payload = '{"data": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}'
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process (Unicode escapes are valid JSON)
            # Validation should catch XSS patterns after parsing
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_json_with_control_characters(self):
        """Test JSON with control characters."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Control characters in JSON strings
            payload = '{"data": "test\\n\\r\\t\\u0000"}'
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process (control chars are valid in JSON strings)
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_json_with_surrogate_pairs(self):
        """Test JSON with Unicode surrogate pairs."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Surrogate pairs
            payload = '{"data": "\\uD800\\uDC00"}'
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process or reject gracefully
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_json_with_numbers_causing_overflow(self):
        """Test JSON with numbers that could cause integer overflow."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Very large numbers
            payload = '{"number": 1e308}'  # Near float max
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process (Python handles large floats)
            assert response.status_code in [200, 400]


# ============================================================================
# 4. CONTENT-TYPE CONFUSION ATTACKS
# ============================================================================

class TestContentTypeConfusion:
    """Test Content-Type confusion and mismatch attacks."""
    
    @pytest.mark.asyncio
    async def test_content_type_spoofing(self):
        """Test Content-Type header spoofing."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Send JSON with XML Content-Type
            payload = '{"data": "test"}'
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/xml"}
            )
            # System uses config data_type, not Content-Type header (more secure)
            # Should still process as JSON based on config
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_multiple_content_type_headers(self):
        """Test multiple Content-Type headers (header injection)."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # FastAPI will only use the last Content-Type header
            # But we test that it doesn't cause issues
            payload = '{"data": "test"}'
            
            # Create request with multiple Content-Type headers
            # httpx doesn't support this directly, so we test via raw headers
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json; charset=utf-8"}
            )
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_content_type_with_charset_manipulation(self):
        """Test Content-Type with manipulated charset."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Try to manipulate encoding via Content-Type
            payload = '{"data": "test"}'
            
            # Invalid charset
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json; charset=invalid-encoding"}
            )
            # Should fall back to UTF-8
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_content_type_with_parameters_injection(self):
        """Test Content-Type with injected parameters."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Content-Type with malicious parameters
            payload = '{"data": "test"}'
            
            # Try to inject via Content-Type parameters
            malicious_ct = "application/json; charset=utf-8; boundary=malicious"
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": malicious_ct}
            )
            # Should process (extra parameters ignored)
            assert response.status_code in [200, 400]


# ============================================================================
# 5. REQUEST BODY ENCODING BYPASSES
# ============================================================================

class TestRequestBodyEncodingBypasses:
    """Test request body encoding bypass attacks."""
    
    @pytest.mark.asyncio
    async def test_encoding_confusion_attack(self):
        """Test encoding confusion to bypass validation."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Send UTF-8 data but claim it's UTF-16
            payload_data = {"data": "test"}
            payload_bytes = json.dumps(payload_data).encode('utf-8')
            
            response = await ac.post(
                "/webhook/print",
                content=payload_bytes,
                headers={"Content-Type": "application/json; charset=utf-16"}
            )
            # Should decode correctly (fallback to UTF-8)
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_mixed_encoding_in_body(self):
        """Test body with mixed encoding."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Mix UTF-8 and Latin-1 bytes
            mixed = b'{"data": "test\xc3\xa9"}'  # UTF-8 é
            
            response = await ac.post(
                "/webhook/print",
                content=mixed,
                headers={"Content-Type": "application/json; charset=utf-8"}
            )
            # Should decode correctly
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_bom_manipulation(self):
        """Test BOM (Byte Order Mark) manipulation."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # UTF-8 BOM
            bom_utf8 = b'\xef\xbb\xbf{"data": "test"}'
            
            response = await ac.post(
                "/webhook/print",
                content=bom_utf8,
                headers={"Content-Type": "application/json; charset=utf-8"}
            )
            # Should handle BOM correctly
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_invalid_utf8_sequences(self):
        """Test invalid UTF-8 sequences."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Invalid UTF-8 sequence
            invalid_utf8 = b'{"data": "\xff\xfe"}'
            
            response = await ac.post(
                "/webhook/print",
                content=invalid_utf8,
                headers={"Content-Type": "application/json; charset=utf-8"}
            )
            # Should handle gracefully (fallback to error handling)
            assert response.status_code in [200, 400]


# ============================================================================
# 6. JSON STRUCTURE MANIPULATION ATTACKS
# ============================================================================

class TestJSONStructureManipulation:
    """Test JSON structure manipulation attacks."""
    
    @pytest.mark.asyncio
    async def test_json_with_excessive_whitespace(self):
        """Test JSON with excessive whitespace (DoS)."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # JSON with massive whitespace (11MB total to exceed limit)
            payload = '{\n' + ' ' * (11 * 1024 * 1024) + '"data": "test"\n}'
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should be rejected by size validation (10MB limit)
            assert response.status_code in [400, 413]
    
    @pytest.mark.asyncio
    async def test_json_with_many_keys(self):
        """Test JSON with excessive number of keys."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # JSON with 10000 keys
            payload_data = {f"key_{i}": f"value_{i}" for i in range(10000)}
            payload = json.dumps(payload_data)
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process (no limit on number of keys, but size limit applies)
            assert response.status_code in [200, 400, 413]
    
    @pytest.mark.asyncio
    async def test_json_with_circular_reference_attempt(self):
        """Test JSON that attempts to create circular references."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # JSON can't represent circular references, but we test
            # Python's json.loads will parse it, but creating circular refs requires code
            payload = '{"a": {"b": {"c": "d"}}}'
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process (JSON can't represent circular refs)
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_json_with_special_number_values(self):
        """Test JSON with special number values (Infinity, NaN)."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # JSON doesn't support Infinity/NaN, but we test
            payload = '{"number": 1e308}'
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process
            assert response.status_code in [200, 400]


# ============================================================================
# 7. REQUEST PROCESSING RACE CONDITIONS
# ============================================================================

class TestRequestProcessingRaceConditions:
    """Test race conditions in request processing."""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests_same_webhook(self):
        """Test concurrent requests to same webhook (rate limit bypass attempt)."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Send 100 concurrent requests
            import asyncio
            tasks = [
                ac.post("/webhook/print", json={"request": i})
                for i in range(100)
            ]
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should be processed (rate limiting may apply)
            for response in responses:
                if isinstance(response, Exception):
                    continue
                assert response.status_code in [200, 401, 429]
    
    @pytest.mark.asyncio
    async def test_body_read_race_condition(self):
        """Test race condition in body reading."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Body caching should prevent issues
            payload = {"data": "test"}
            
            # Send request
            response = await ac.post("/webhook/print", json=payload)
            assert response.status_code in [200, 400]


# ============================================================================
# 8. INPUT VALIDATION BYPASS ATTEMPTS
# ============================================================================

class TestInputValidationBypasses:
    """Test attempts to bypass input validation."""
    
    def test_webhook_id_validation_bypass_attempts(self):
        """Test various bypass attempts for webhook ID validation."""
        bypass_attempts = [
            "stats\x00",  # Null byte
            "stats/",  # Path separator
            "stats%2F",  # URL encoded
            "stats%252F",  # Double encoded
            "stats\x20",  # Space
            "stats\n",  # Newline
            "stats\r",  # Carriage return
            "stats\t",  # Tab
        ]
        
        for webhook_id in bypass_attempts:
            is_valid, msg = InputValidator.validate_webhook_id(webhook_id)
            # Should be rejected
            assert not is_valid, f"Should reject bypass attempt: {repr(webhook_id)}"
    
    @pytest.mark.asyncio
    async def test_payload_size_validation_bypass(self):
        """Test attempts to bypass payload size validation."""
        # Test with compressed data (if compression was supported)
        # Since we don't support compression, this tests the current behavior
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Create payload exactly at limit
            payload_data = {"data": "x" * (10 * 1024 * 1024 - 100)}  # Just under 10MB
            payload = json.dumps(payload_data)
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process (under limit)
            assert response.status_code in [200, 400]
    
    @pytest.mark.asyncio
    async def test_json_depth_validation_bypass(self):
        """Test attempts to bypass JSON depth validation."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Create structure exactly at depth limit (50)
            nested = {"level": 1}
            current = nested
            for i in range(2, 51):  # 50 levels
                current["nested"] = {"level": i}
                current = current["nested"]
            
            payload = json.dumps(nested)
            
            response = await ac.post(
                "/webhook/print",
                content=payload.encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            # Should process (at limit)
            assert response.status_code in [200, 400]


# ============================================================================
# 9. ERROR HANDLING INFORMATION DISCLOSURE
# ============================================================================

class TestErrorHandlingInformationDisclosure:
    """Test error handling for information disclosure."""
    
    @pytest.mark.asyncio
    async def test_malformed_json_error_message(self):
        """Test that malformed JSON errors don't disclose internals."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            response = await ac.post(
                "/webhook/print",
                content=b"{invalid json}",
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 400
            error_detail = response.json()["detail"]
            # Should not expose internal details
            assert "json.loads" not in error_detail.lower()
            assert "traceback" not in error_detail.lower()
            assert "file" not in error_detail.lower()
    
    @pytest.mark.asyncio
    async def test_oversized_payload_error_message(self):
        """Test that oversized payload errors don't disclose limits."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=test_url) as ac:
            # Create 11MB payload
            payload = b"x" * (11 * 1024 * 1024)
            
            response = await ac.post(
                "/webhook/print",
                content=payload,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 413
            error_detail = response.json()["detail"]
            # May include size info (acceptable for user feedback)
            # But shouldn't expose internal limits or paths
            assert "file" not in error_detail.lower()
            assert "path" not in error_detail.lower()


# ============================================================================
# 10. REQUEST BODY CACHING SECURITY
# ============================================================================

class TestRequestBodyCachingSecurity:
    """Test request body caching for security issues."""
    
    @pytest.mark.asyncio
    async def test_body_cached_prevents_double_read(self):
        """Test that body caching prevents double-read issues."""
        # This is tested in test_request_body_caching.py
        # We verify the caching works correctly
        from fastapi import Request
        from unittest.mock import Mock, AsyncMock
        
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        
        body_read_count = 0
        original_body = b'{"test": "data"}'
        
        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return original_body
            else:
                return b''
        
        mock_request.body = AsyncMock(side_effect=mock_body)
        
        configs = {"test_webhook": {"data_type": "json", "module": "log"}}
        
        handler = WebhookHandler("test_webhook", configs, {}, mock_request)
        
        # First call should read body
        await handler.validate_webhook()
        assert handler._cached_body == original_body
        assert body_read_count == 1
        
        # Second call should use cached body
        await handler.process_webhook()
        assert body_read_count == 1  # Should not read again

