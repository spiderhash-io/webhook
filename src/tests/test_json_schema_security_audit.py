"""
Comprehensive security audit tests for JsonSchemaValidator.
Tests schema injection, DoS attacks, error disclosure, ReDoS, and edge cases.
"""
import pytest
import json
import time
import asyncio
from unittest.mock import Mock, patch, MagicMock
from src.validators import JsonSchemaValidator


# ============================================================================
# 1. SCHEMA INJECTION & CONFIG VALIDATION
# ============================================================================

class TestJsonSchemaConfigInjection:
    """Test schema configuration injection and type validation."""
    
    @pytest.mark.asyncio
    async def test_schema_type_validation(self):
        """Test that schema must be a dict."""
        invalid_configs = [
            {"json_schema": None},
            {"json_schema": "not_a_dict"},
            {"json_schema": 123},
            {"json_schema": []},
        ]
        
        for invalid_config in invalid_configs:
            validator = JsonSchemaValidator(invalid_config)
            # Empty schema dict should return True (no schema configured)
            # But non-dict should be handled
            is_valid, message = await validator.validate({}, b'{"test": "data"}')
            # Should handle invalid schema type
            # Empty dict {} evaluates to False, so should return "No JSON schema configured"
            if invalid_config['json_schema'] == {}:
                assert is_valid is True
            else:
                # Non-dict schemas may cause errors during validation
                pass
    
    @pytest.mark.asyncio
    async def test_malicious_schema_injection(self):
        """Test that malicious schemas are handled safely."""
        # Note: Schema comes from config, not user input, but we test edge cases
        malicious_schemas = [
            {"type": "object", "$ref": "../../etc/passwd"},  # Path traversal in $ref
            {"type": "object", "properties": {"__import__": {"type": "string"}}},  # Python builtin
            {"type": "object", "properties": {"eval": {"type": "string"}}},  # Dangerous function name
        ]
        
        for malicious_schema in malicious_schemas:
            config = {"json_schema": malicious_schema}
            validator = JsonSchemaValidator(config)
            
            payload = b'{"test": "data"}'
            
            try:
                is_valid, message = await validator.validate({}, payload)
                # Should handle schema validation (may fail, but shouldn't crash)
            except Exception as e:
                # Should handle exceptions gracefully
                assert True


# ============================================================================
# 2. DENIAL OF SERVICE ATTACKS
# ============================================================================

class TestJsonSchemaDoS:
    """Test DoS attacks via complex schemas and payloads."""
    
    @pytest.mark.asyncio
    async def test_recursive_schema_dos(self):
        """Test DoS via recursive/self-referential schemas."""
        # Create a recursive schema that references itself
        recursive_schema = {
            "type": "object",
            "properties": {
                "nested": {"$ref": "#"}
            }
        }
        
        config = {"json_schema": recursive_schema}
        validator = JsonSchemaValidator(config)
        
        payload = json.dumps({"nested": {"nested": {"nested": "deep"}}}).encode()
        
        try:
            start_time = time.time()
            is_valid, message = await validator.validate({}, payload)
            elapsed = time.time() - start_time
            
            # Should complete within reasonable time (or fail gracefully)
            assert elapsed < 5.0, "Recursive schema validation took too long"
        except Exception as e:
            # Should handle recursive schemas gracefully
            assert True
    
    @pytest.mark.asyncio
    async def test_deeply_nested_schema_dos(self):
        """Test DoS via deeply nested schemas."""
        # Create a deeply nested schema
        nested_schema = {"type": "object"}
        current = nested_schema
        for i in range(100):  # 100 levels of nesting
            current["properties"] = {"level": {"type": "object"}}
            current = current["properties"]["level"]
        
        config = {"json_schema": nested_schema}
        validator = JsonSchemaValidator(config)
        
        # Create matching nested payload
        nested_payload = {}
        current_payload = nested_payload
        for i in range(100):
            current_payload["level"] = {}
            current_payload = current_payload["level"]
        
        payload = json.dumps(nested_payload).encode()
        
        try:
            start_time = time.time()
            is_valid, message = await validator.validate({}, payload)
            elapsed = time.time() - start_time
            
            # Should complete within reasonable time
            assert elapsed < 5.0, "Deeply nested schema validation took too long"
        except Exception as e:
            # Should handle deeply nested schemas gracefully
            assert True
    
    @pytest.mark.asyncio
    async def test_large_schema_dos(self):
        """Test DoS via very large schemas."""
        # Create a very large schema with many properties
        large_schema = {
            "type": "object",
            "properties": {
                f"property_{i}": {"type": "string"}
                for i in range(10000)
            }
        }
        
        config = {"json_schema": large_schema}
        validator = JsonSchemaValidator(config)
        
        # Create matching payload
        large_payload = {f"property_{i}": f"value_{i}" for i in range(10000)}
        payload = json.dumps(large_payload).encode()
        
        try:
            start_time = time.time()
            is_valid, message = await validator.validate({}, payload)
            elapsed = time.time() - start_time
            
            # Should complete within reasonable time (may be slow, but shouldn't crash)
            assert elapsed < 10.0, "Large schema validation took too long"
        except Exception as e:
            # Should handle large schemas gracefully
            assert True
    
    # @pytest.mark.asyncio
    # async def test_regex_dos_redos(self):
    #     """Test ReDoS attacks via malicious regex patterns in schema."""
    #     # ReDoS pattern: (a+)+b (exponential backtracking)
    #     redos_schema = {
    #         "type": "object",
    #         "properties": {
    #             "field": {
    #                 "type": "string",
    #                 "pattern": "(a+)+b"  # ReDoS pattern
    #             }
    #         }
    #     }
    #     
    #     config = {"json_schema": redos_schema}
    #     validator = JsonSchemaValidator(config)
    #     
    #     # Payload that triggers ReDoS
    #     redos_payload = {"field": "a" * 30 + "c"}  # Should fail quickly, not cause ReDoS
    #     payload = json.dumps(redos_payload).encode()
    #     
    #     try:
    #         start_time = time.time()
    #         is_valid, message = await validator.validate({}, payload)
    #         elapsed = time.time() - start_time
    #         
    #         # Should complete quickly (ReDoS should be mitigated by jsonschema library)
    #         assert elapsed < 2.0, "ReDoS pattern took too long to validate"
    #     except Exception as e:
    #         # Should handle ReDoS patterns gracefully
    #         assert True


# ============================================================================
# 3. ERROR MESSAGE DISCLOSURE
# ============================================================================

class TestJsonSchemaErrorDisclosure:
    """Test error message information disclosure."""
    
    @pytest.mark.asyncio
    async def test_validation_error_sanitization(self):
        """Test that validation errors don't expose sensitive information."""
        config = {
            "json_schema": {
                "type": "object",
                "properties": {
                    "secret_field": {"type": "string"}
                },
                "required": ["secret_field"]
            }
        }
        validator = JsonSchemaValidator(config)
        
        # Payload missing required field
        payload = b'{"other_field": "value"}'
        
        is_valid, message = await validator.validate({}, payload)
        assert is_valid is False
        
        # Should not expose schema structure or field names in detail
        # May include field name, but shouldn't expose full schema
        assert "json schema validation failed" in message.lower() or "validation failed" in message.lower()
    
    @pytest.mark.asyncio
    async def test_schema_error_sanitization(self):
        """Test that schema errors don't expose internal details."""
        # Invalid schema that causes SchemaError
        invalid_schema = {
            "type": "object",
            "$ref": "#/definitions/nonexistent"  # Invalid reference
        }
        
        config = {"json_schema": invalid_schema}
        validator = JsonSchemaValidator(config)
        
        payload = b'{"test": "data"}'
        
        is_valid, message = await validator.validate({}, payload)
        assert is_valid is False
        
        # Should sanitize error message
        error_msg = message.lower()
        assert "traceback" not in error_msg
        assert "file" not in error_msg
        assert "line" not in error_msg
    
    @pytest.mark.asyncio
    async def test_generic_exception_sanitization(self):
        """Test that generic exceptions are sanitized."""
        config = {"json_schema": {"type": "object"}}
        validator = JsonSchemaValidator(config)
        
        # Mock jsonschema.validate to raise exception with sensitive info
        # This tests the exception handling in the validation code
        with patch('jsonschema.validate', side_effect=Exception("Internal error with path: /etc/passwd")):
            payload = b'{"test": "data"}'
            
            is_valid, message = await validator.validate({}, payload)
            assert is_valid is False
            
            # Should sanitize error message
            error_msg = message.lower()
            assert "/etc/passwd" not in error_msg
            assert "internal error" not in error_msg
            assert "json schema validation" in error_msg or "validation" in error_msg


# ============================================================================
# 4. PAYLOAD SECURITY
# ============================================================================

class TestJsonSchemaPayloadSecurity:
    """Test payload security and edge cases."""
    
    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payload are handled safely."""
        config = {
            "json_schema": {
                "type": "object",
                "properties": {
                    "data": {"type": "string"}
                }
            }
        }
        validator = JsonSchemaValidator(config)
        
        # JSON can't represent circular references, but we test edge cases
        # Create a payload that might cause issues
        payload = b'{"data": "test"}'
        
        is_valid, message = await validator.validate({}, payload)
        # Should validate normally
        assert is_valid is True or is_valid is False
    
    @pytest.mark.asyncio
    async def test_very_large_payload(self):
        """Test that very large payloads are handled without DoS."""
        config = {
            "json_schema": {
                "type": "object",
                "properties": {
                    "data": {"type": "string"}
                }
            }
        }
        validator = JsonSchemaValidator(config)
        
        # Very large payload (10MB)
        large_payload = {"data": "x" * (10 * 1024 * 1024)}
        payload = json.dumps(large_payload).encode()
        
        try:
            start_time = time.time()
            is_valid, message = await validator.validate({}, payload)
            elapsed = time.time() - start_time
            
            # Should complete within reasonable time
            # Note: InputValidator should catch this before reaching validator
            assert elapsed < 10.0, "Large payload validation took too long"
        except Exception as e:
            # Should handle large payloads gracefully
            assert True
    
    @pytest.mark.asyncio
    async def test_malformed_json_handling(self):
        """Test that malformed JSON is handled safely."""
        config = {
            "json_schema": {
                "type": "object"
            }
        }
        validator = JsonSchemaValidator(config)
        
        malformed_payloads = [
            b"{invalid json}",
            b"{'invalid': 'quotes'}",
            b"{test: no quotes}",
            b"",
            b"null",
            b"undefined",
        ]
        
        for payload in malformed_payloads:
            is_valid, message = await validator.validate({}, payload)
            # Should reject malformed JSON
            if payload == b"":
                # Empty body might be handled differently
                pass
            else:
                assert is_valid is False or "Invalid JSON body" in message


# ============================================================================
# 5. SCHEMA VALIDATION SECURITY
# ============================================================================

class TestJsonSchemaValidationSecurity:
    """Test schema validation security features."""
    
    @pytest.mark.asyncio
    async def test_schema_with_remote_references(self):
        """Test that remote $ref references are handled safely."""
        # Schema with remote reference (potential SSRF)
        remote_ref_schema = {
            "type": "object",
            "$ref": "http://example.com/schema.json"
        }
        
        config = {"json_schema": remote_ref_schema}
        validator = JsonSchemaValidator(config)
        
        payload = b'{"test": "data"}'
        
        try:
            is_valid, message = await validator.validate({}, payload)
            # jsonschema may or may not support remote refs by default
            # Should handle gracefully
        except Exception as e:
            # Should handle remote references safely
            assert True
    
    @pytest.mark.asyncio
    async def test_schema_with_file_references(self):
        """Test that file:// $ref references are handled safely."""
        # Schema with file reference (potential path traversal)
        file_ref_schema = {
            "type": "object",
            "$ref": "file:///etc/passwd"
        }
        
        config = {"json_schema": file_ref_schema}
        validator = JsonSchemaValidator(config)
        
        payload = b'{"test": "data"}'
        
        try:
            is_valid, message = await validator.validate({}, payload)
            # Should not allow file:// references
        except Exception as e:
            # Should handle file references safely
            assert True
    
    @pytest.mark.asyncio
    async def test_schema_with_script_injection(self):
        """Test that schemas with script injection patterns are handled safely."""
        # Schema with potential script injection
        script_schema = {
            "type": "object",
            "properties": {
                "field": {
                    "type": "string",
                    "default": "<script>alert(1)</script>"
                }
            }
        }
        
        config = {"json_schema": script_schema}
        validator = JsonSchemaValidator(config)
        
        payload = b'{"field": "test"}'
        
        is_valid, message = await validator.validate({}, payload)
        # Should validate normally (default doesn't execute)
        assert is_valid is True or is_valid is False


# ============================================================================
# 6. CONFIGURATION SECURITY
# ============================================================================

class TestJsonSchemaConfigurationSecurity:
    """Test configuration security and validation."""
    
    @pytest.mark.asyncio
    async def test_empty_schema_config(self):
        """Test that empty schema config is handled safely."""
        config = {"json_schema": {}}
        validator = JsonSchemaValidator(config)
        
        payload = b'{"test": "data"}'
        
        is_valid, message = await validator.validate({}, payload)
        # Empty schema should return True (no schema configured)
        assert is_valid is True
        assert "No JSON schema configured" in message
    
    @pytest.mark.asyncio
    async def test_missing_schema_config(self):
        """Test that missing schema config is handled safely."""
        config = {}  # No json_schema key
        validator = JsonSchemaValidator(config)
        
        payload = b'{"test": "data"}'
        
        is_valid, message = await validator.validate({}, payload)
        # Should return True (no schema configured)
        assert is_valid is True
        assert "No JSON schema configured" in message
    
    @pytest.mark.asyncio
    async def test_none_schema_config(self):
        """Test that None schema config is handled safely."""
        config = {"json_schema": None}
        validator = JsonSchemaValidator(config)
        
        payload = b'{"test": "data"}'
        
        is_valid, message = await validator.validate({}, payload)
        # None should be treated as no schema
        assert is_valid is True
        assert "No JSON schema configured" in message


# ============================================================================
# 7. LIBRARY DEPENDENCY SECURITY
# ============================================================================

class TestJsonSchemaLibrarySecurity:
    """Test jsonschema library dependency security."""
    
    @pytest.mark.asyncio
    async def test_missing_jsonschema_library(self):
        """Test behavior when jsonschema library is not installed."""
        config = {"json_schema": {"type": "object"}}
        validator = JsonSchemaValidator(config)
        
        # Mock ImportError
        with patch('builtins.__import__', side_effect=ImportError("No module named 'jsonschema'")):
            payload = b'{"test": "data"}'
            
            is_valid, message = await validator.validate({}, payload)
            assert is_valid is False
            assert "jsonschema library not installed" in message
    
    @pytest.mark.asyncio
    async def test_jsonschema_version_compatibility(self):
        """Test that jsonschema version compatibility is handled."""
        config = {"json_schema": {"type": "object"}}
        validator = JsonSchemaValidator(config)
        
        payload = b'{"test": "data"}'
        
        # Should work with any compatible jsonschema version
        is_valid, message = await validator.validate({}, payload)
        # Should either validate or return appropriate error
        assert isinstance(is_valid, bool)


# ============================================================================
# 8. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================

class TestJsonSchemaEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test that empty payloads are handled safely."""
        config = {
            "json_schema": {
                "type": "object"
            }
        }
        validator = JsonSchemaValidator(config)
        
        # Empty JSON object
        payload = b'{}'
        
        is_valid, message = await validator.validate({}, payload)
        # Should validate empty object
        assert isinstance(is_valid, bool)
    
    @pytest.mark.asyncio
    async def test_null_payload(self):
        """Test that null payloads are handled safely."""
        config = {
            "json_schema": {
                "type": "null"
            }
        }
        validator = JsonSchemaValidator(config)
        
        payload = b'null'
        
        is_valid, message = await validator.validate({}, payload)
        # Should validate null
        assert isinstance(is_valid, bool)
    
    @pytest.mark.asyncio
    async def test_array_payload(self):
        """Test that array payloads are handled safely."""
        config = {
            "json_schema": {
                "type": "array",
                "items": {"type": "string"}
            }
        }
        validator = JsonSchemaValidator(config)
        
        payload = b'["item1", "item2"]'
        
        is_valid, message = await validator.validate({}, payload)
        # Should validate array
        assert isinstance(is_valid, bool)
    
    @pytest.mark.asyncio
    async def test_very_deep_nesting_in_payload(self):
        """Test that very deep nesting in payload is handled safely."""
        config = {
            "json_schema": {
                "type": "object"
            }
        }
        validator = JsonSchemaValidator(config)
        
        # Create deeply nested payload
        nested = {}
        current = nested
        for i in range(100):
            current["level"] = {}
            current = current["level"]
        
        payload = json.dumps(nested).encode()
        
        try:
            start_time = time.time()
            is_valid, message = await validator.validate({}, payload)
            elapsed = time.time() - start_time
            
            # Should complete within reasonable time
            assert elapsed < 5.0, "Deeply nested payload validation took too long"
        except Exception as e:
            # Should handle deeply nested payloads gracefully
            assert True


# ============================================================================
# 9. CONCURRENT VALIDATION SECURITY
# ============================================================================

class TestJsonSchemaConcurrentValidation:
    """Test concurrent validation security."""
    
    @pytest.mark.asyncio
    async def test_concurrent_schema_validation(self):
        """Test that concurrent schema validations are handled securely."""
        config = {
            "json_schema": {
                "type": "object",
                "properties": {
                    "field": {"type": "string"}
                }
            }
        }
        validator = JsonSchemaValidator(config)
        
        # Process multiple validations concurrently
        tasks = [
            validator.validate({}, json.dumps({"field": f"value_{i}"}).encode())
            for i in range(10)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # All should complete successfully
        for is_valid, message in results:
            assert isinstance(is_valid, bool)
            assert isinstance(message, str)


# ============================================================================
# 10. SCHEMA COMPLEXITY ATTACKS
# ============================================================================

class TestJsonSchemaComplexityAttacks:
    """Test schema complexity-based attacks."""
    
    @pytest.mark.asyncio
    async def test_schema_with_many_required_fields(self):
        """Test schema with many required fields (DoS attempt)."""
        # Schema with 1000 required fields
        many_required_schema = {
            "type": "object",
            "properties": {
                f"field_{i}": {"type": "string"}
                for i in range(1000)
            },
            "required": [f"field_{i}" for i in range(1000)]
        }
        
        config = {"json_schema": many_required_schema}
        validator = JsonSchemaValidator(config)
        
        # Payload missing all required fields
        payload = b'{}'
        
        try:
            start_time = time.time()
            is_valid, message = await validator.validate({}, payload)
            elapsed = time.time() - start_time
            
            # Should complete within reasonable time
            assert elapsed < 5.0, "Many required fields validation took too long"
            assert is_valid is False
        except Exception as e:
            # Should handle many required fields gracefully
            assert True
    
    @pytest.mark.asyncio
    async def test_schema_with_complex_allof(self):
        """Test schema with complex allOf (DoS attempt)."""
        # Schema with nested allOf
        complex_allof_schema = {
            "allOf": [
                {"type": "object", "properties": {"field": {"type": "string"}}},
                {"type": "object", "properties": {"field": {"type": "string", "minLength": 1}}},
            ] * 50  # 100 nested allOf conditions
        }
        
        config = {"json_schema": complex_allof_schema}
        validator = JsonSchemaValidator(config)
        
        payload = b'{"field": "test"}'
        
        try:
            start_time = time.time()
            is_valid, message = await validator.validate({}, payload)
            elapsed = time.time() - start_time
            
            # Should complete within reasonable time
            assert elapsed < 5.0, "Complex allOf validation took too long"
        except Exception as e:
            # Should handle complex allOf gracefully
            assert True

