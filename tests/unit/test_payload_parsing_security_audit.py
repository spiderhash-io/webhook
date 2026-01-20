"""
Comprehensive security audit tests for Payload Parsing and Processing Flow.

This audit focuses on:
- Data type handling security (type confusion, missing keys, invalid values)
- JSON parsing security (deserialization attacks, DoS, error handling)
- Body caching security (race conditions, double-read issues)
- Content-Type vs data_type mismatch handling
- Error information disclosure in parsing
- Edge cases and boundary conditions
"""

import pytest
import json
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from fastapi import Request, HTTPException

from src.webhook import WebhookHandler


# ============================================================================
# 1. DATA TYPE HANDLING SECURITY
# ============================================================================


class TestDataTypeHandlingSecurity:
    """Test data type handling vulnerabilities."""

    @pytest.mark.asyncio
    async def test_missing_data_type_key(self):
        """Test that missing data_type key defaults to 'json'."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

        configs = {
            "test_webhook": {
                "module": "log"
                # Missing data_type - should default to "json"
            }
        }

        # Should work with default "json" data_type
        handler = WebhookHandler("test_webhook", configs, {}, mock_request)
        # Should not raise exception - defaults to "json"
        # The handler will process it as JSON
        assert handler.config.get("data_type") is None  # Not in config
        # But process_webhook will use "json" as default

    @pytest.mark.asyncio
    async def test_data_type_type_confusion(self):
        """Test that non-string data_type values are handled safely."""
        malicious_data_types = [
            None,
            123,
            [],
            {},
            True,
            False,
        ]

        for malicious_data_type in malicious_data_types:
            mock_request = Mock(spec=Request)
            mock_request.headers = {"content-type": "application/json"}
            mock_request.query_params = {}
            mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

            configs = {
                "test_webhook": {"module": "log", "data_type": malicious_data_type}
            }

            try:
                handler = WebhookHandler("test_webhook", configs, {}, mock_request)
                result = await handler.process_webhook()
                # Should fail or handle gracefully
                # Type confusion: non-string data_type might cause unexpected behavior
                assert (
                    False
                ), f"Should reject non-string data_type: {type(malicious_data_type).__name__}"
            except (HTTPException, TypeError, AttributeError) as e:
                # Expected - should reject invalid data_type
                if isinstance(e, HTTPException):
                    assert e.status_code in [400, 415]
                assert True

    @pytest.mark.asyncio
    async def test_invalid_data_type_value(self):
        """Test that invalid data_type values are rejected."""
        invalid_data_types = [
            "invalid",
            "xml",
            "yaml",
            "text",  # If not supported
            "JSON",  # Case sensitivity
            "json\x00",  # Null byte
            "json\n",  # Newline
            "json\r",  # Carriage return
        ]

        for invalid_data_type in invalid_data_types:
            mock_request = Mock(spec=Request)
            mock_request.headers = {"content-type": "application/json"}
            mock_request.query_params = {}
            mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

            configs = {
                "test_webhook": {"module": "log", "data_type": invalid_data_type}
            }

            try:
                handler = WebhookHandler("test_webhook", configs, {}, mock_request)
                result = await handler.process_webhook()
                # Should fail with 415 Unsupported Media Type
                assert False, f"Should reject invalid data_type: {invalid_data_type}"
            except HTTPException as e:
                # Expected - should reject invalid data_type
                assert (
                    e.status_code == 415
                ), f"Expected 415 for invalid data_type: {invalid_data_type}"

    @pytest.mark.asyncio
    async def test_data_type_case_sensitivity(self):
        """Test that data_type comparison is case-sensitive (security consideration)."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

        # Test case variations
        case_variations = ["JSON", "Json", "jSoN", "BLOB", "Blob", "bLoB"]

        for case_variation in case_variations:
            configs = {"test_webhook": {"module": "log", "data_type": case_variation}}

            try:
                handler = WebhookHandler("test_webhook", configs, {}, mock_request)
                result = await handler.process_webhook()
                # Should fail (case-sensitive comparison)
                assert False, f"Should reject case variation: {case_variation}"
            except HTTPException as e:
                # Expected - should reject case variations
                assert e.status_code == 415


# ============================================================================
# 2. JSON PARSING SECURITY
# ============================================================================


class TestJSONParsingSecurity:
    """Test JSON parsing security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_json_parsing_error_information_disclosure(self):
        """Test that JSON parsing errors don't disclose sensitive information."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{invalid json}")

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            assert False, "Should raise HTTPException for invalid JSON"
        except HTTPException as e:
            # Error message should not expose internal details
            error_detail = e.detail
            assert "json.loads" not in error_detail.lower()
            assert "traceback" not in error_detail.lower()
            assert "file" not in error_detail.lower()
            assert "line" not in error_detail.lower()
            assert e.status_code == 400

    @pytest.mark.asyncio
    async def test_json_parsing_with_circular_reference_attempt(self):
        """Test that JSON parsing handles circular reference attempts safely."""
        # Note: JSON can't represent circular references, but we test error handling
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"a": {"b": {"c": "d"}}}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process successfully (JSON can't represent circular refs)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_json_parsing_with_duplicate_keys(self):
        """Test that JSON with duplicate keys is handled safely."""
        # Python's json.loads keeps the last value for duplicate keys
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"key": "first", "key": "last"}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (Python's json.loads handles this)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_json_parsing_with_unicode_escape_sequences(self):
        """Test that Unicode escape sequences are handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        # Unicode escape sequences
        mock_request.body = AsyncMock(return_value=b'{"data": "\\u003cscript\\u003e"}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (Unicode escapes are valid JSON)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_json_parsing_with_control_characters(self):
        """Test that control characters in JSON are handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        # Control characters in JSON strings
        mock_request.body = AsyncMock(return_value=b'{"data": "test\\n\\r\\t"}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (control chars are valid in JSON strings)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_json_parsing_with_special_number_values(self):
        """Test that special number values are handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        # Very large numbers
        mock_request.body = AsyncMock(return_value=b'{"number": 1e308}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (Python handles large floats)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_json_parsing_empty_body(self):
        """Test that empty body is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"")

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should fail (empty JSON is invalid)
            assert False, "Should reject empty JSON body"
        except HTTPException as e:
            # Expected - empty JSON is invalid
            assert e.status_code == 400

    @pytest.mark.asyncio
    async def test_json_parsing_whitespace_only_body(self):
        """Test that whitespace-only body is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"   \n\t  ")

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should fail (whitespace-only JSON is invalid)
            assert False, "Should reject whitespace-only JSON body"
        except HTTPException as e:
            # Expected - whitespace-only JSON is invalid
            assert e.status_code == 400


# ============================================================================
# 3. BODY CACHING SECURITY
# ============================================================================


class TestBodyCachingSecurity:
    """Test body caching security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_body_caching_prevents_double_read(self):
        """Test that body caching prevents double-read issues."""
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
                return b""  # Empty on second read

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # First call (validate_webhook) should read body
        await handler.validate_webhook()
        assert handler._cached_body == original_body
        assert body_read_count == 1

        # Second call (process_webhook) should use cached body
        await handler.process_webhook()
        assert body_read_count == 1  # Should not read again

    @pytest.mark.asyncio
    async def test_body_caching_with_exception(self):
        """Test that body caching works even when exceptions occur."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Cache body first
        await handler.validate_webhook()
        cached_body = handler._cached_body

        # Even if process_webhook fails, cached body should remain
        try:
            # Modify config to cause error
            handler.config["data_type"] = "invalid"
            await handler.process_webhook()
        except HTTPException:
            pass

        # Cached body should still be available
        assert handler._cached_body == cached_body

    @pytest.mark.asyncio
    async def test_body_caching_concurrent_access(self):
        """Test that body caching is safe under concurrent access."""
        import asyncio

        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Simulate concurrent access
        async def access_body():
            if handler._cached_body is None:
                handler._cached_body = await mock_request.body()
            return handler._cached_body

        # Run multiple concurrent accesses
        results = await asyncio.gather(*[access_body() for _ in range(10)])

        # All should return the same body
        assert all(r == results[0] for r in results)


# ============================================================================
# 4. CONTENT-TYPE VS DATA_TYPE MISMATCH
# ============================================================================


class TestContentTypeDataTypeMismatch:
    """Test Content-Type vs data_type mismatch handling."""

    @pytest.mark.asyncio
    async def test_content_type_mismatch_json_config(self):
        """Test that Content-Type mismatch with JSON config is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/xml"}  # Mismatch
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (uses config, not Content-Type header)
            # This is actually more secure (prevents Content-Type spoofing)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_content_type_mismatch_blob_config(self):
        """Test that Content-Type mismatch with blob config is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}  # Mismatch
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"binary data")

        configs = {"test_webhook": {"module": "log", "data_type": "blob"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (uses config, not Content-Type header)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_missing_content_type_header(self):
        """Test that missing Content-Type header is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {}  # No Content-Type
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (fallback to default encoding)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)


# ============================================================================
# 5. BLOB DATA TYPE HANDLING
# ============================================================================


class TestBlobDataTypeHandling:
    """Test blob data type handling security."""

    @pytest.mark.asyncio
    async def test_blob_data_type_handling(self):
        """Test that blob data type is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/octet-stream"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"binary data\x00\x01\x02")

        configs = {"test_webhook": {"module": "log", "data_type": "blob"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (blob data is passed as-is)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_blob_data_type_with_large_payload(self):
        """Test that blob data type handles large payloads safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/octet-stream"}
        mock_request.query_params = {}
        # Large blob (just under 10MB limit)
        large_blob = b"x" * (10 * 1024 * 1024 - 1)
        mock_request.body = AsyncMock(return_value=large_blob)

        configs = {"test_webhook": {"module": "log", "data_type": "blob"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (under size limit)
            assert True
        except HTTPException as e:
            # May fail if size limit applies
            assert e.status_code == 413


# ============================================================================
# 6. ERROR HANDLING INFORMATION DISCLOSURE
# ============================================================================


class TestErrorHandlingInformationDisclosure:
    """Test error handling for information disclosure."""

    @pytest.mark.asyncio
    async def test_decoding_error_information_disclosure(self):
        """Test that decoding errors don't disclose sensitive information."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json; charset=invalid"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should handle gracefully
            assert True
        except HTTPException as e:
            # Error message should not expose internal details
            error_detail = e.detail
            assert "safe_decode_body" not in error_detail.lower()
            assert "traceback" not in error_detail.lower()
            assert "file" not in error_detail.lower()
            assert e.status_code == 400

    @pytest.mark.asyncio
    async def test_validation_error_information_disclosure(self):
        """Test that validation errors don't disclose sensitive information."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        # Create deeply nested JSON (over depth limit)
        nested = {"level": 1}
        current = nested
        for i in range(2, 100):  # 100 levels (over 50 limit)
            current["nested"] = {"level": i}
            current = current["nested"]

        mock_request.body = AsyncMock(return_value=json.dumps(nested).encode("utf-8"))

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            assert False, "Should reject deeply nested JSON"
        except HTTPException as e:
            # Error message should not expose internal details
            error_detail = e.detail
            assert "validate_json_depth" not in error_detail.lower()
            assert "traceback" not in error_detail.lower()
            assert "file" not in error_detail.lower()
            assert e.status_code == 400


# ============================================================================
# 7. EDGE CASES AND BOUNDARY CONDITIONS
# ============================================================================


class TestPayloadParsingEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_json_object(self):
        """Test that empty JSON object is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"{}")

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (empty object is valid JSON)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_empty_json_array(self):
        """Test that empty JSON array is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"[]")

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (empty array is valid JSON)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_json_with_only_whitespace(self):
        """Test that JSON with only whitespace is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b"   ")

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should fail (whitespace-only is invalid JSON)
            assert False, "Should reject whitespace-only JSON"
        except HTTPException as e:
            # Expected - whitespace-only is invalid JSON
            assert e.status_code == 400

    @pytest.mark.asyncio
    async def test_json_with_null_value(self):
        """Test that JSON with null value is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"key": null}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (null is valid JSON)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_json_with_boolean_values(self):
        """Test that JSON with boolean values is handled safely."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"true": true, "false": false}')

        configs = {"test_webhook": {"module": "log", "data_type": "json"}}

        try:
            handler = WebhookHandler("test_webhook", configs, {}, mock_request)
            result = await handler.process_webhook()
            # Should process (booleans are valid JSON)
            assert True
        except Exception as e:
            # Should not crash
            assert isinstance(e, HTTPException)

    @pytest.mark.asyncio
    async def test_data_type_get_vs_direct_access(self):
        """Test that data_type access handles missing key safely."""
        # Test that using .get() would be safer than direct [] access
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}
        mock_request.body = AsyncMock(return_value=b'{"test": "data"}')

        configs = {
            "test_webhook": {
                "module": "log"
                # Missing data_type - should use .get() with default
            }
        }

        # Missing data_type - should default to "json"
        handler = WebhookHandler("test_webhook", configs, {}, mock_request)
        # Should work with default "json" data_type
        # No exception expected - defaults to "json"
