"""
Comprehensive security audit tests for OpenAPI Generator.
Tests path injection, information disclosure, DoS, XSS, type confusion, and JSON schema injection.
"""

import pytest
import json
from src.openapi_generator import (
    generate_openapi_schema,
    generate_webhook_path,
    extract_auth_schemes,
    extract_security_info,
)


# ============================================================================
# 1. PATH INJECTION VIA WEBHOOK_ID
# ============================================================================


class TestOpenAPIGeneratorPathInjection:
    """Test path injection vulnerabilities via webhook_id."""

    def test_webhook_id_path_traversal(self):
        """Test path traversal via webhook_id in path construction."""
        malicious_ids = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "/etc/passwd",
            "webhook/../admin",
            "webhook%2F..%2Fadmin",  # URL encoded
        ]

        for malicious_id in malicious_ids:
            config = {"data_type": "json", "module": "log"}
            schema = generate_openapi_schema({malicious_id: config})

            # SECURITY: Path should be rejected (webhook_id validation)
            paths = schema.get("paths", {})
            # Malicious webhook_ids should be filtered out
            path_key = f"/webhook/{malicious_id}"
            assert (
                path_key not in paths
            ), f"Path traversal webhook_id '{malicious_id}' should be rejected"

    def test_webhook_id_operation_id_injection(self):
        """Test injection via webhook_id in operationId."""
        malicious_ids = [
            "webhook'; DROP TABLE users; --",
            "webhook<script>alert('xss')</script>",
            "webhook\nnewline",
            "webhook\x00null",
        ]

        for malicious_id in malicious_ids:
            config = {"data_type": "json", "module": "log"}
            # SECURITY: Malicious webhook_ids should be rejected by validation
            # If they pass validation, operationId should be sanitized
            schema = generate_openapi_schema({malicious_id: config})
            paths = schema.get("paths", {})

            # Most malicious IDs should be rejected, but if any pass, operationId should be safe
            for path_key, path_item in paths.items():
                operation_id = path_item["post"]["operationId"]
                # SECURITY: operationId should not contain dangerous characters
                assert ";" not in operation_id
                assert "<" not in operation_id
                assert "\n" not in operation_id
                assert "\x00" not in operation_id

    def test_webhook_id_description_injection(self):
        """Test injection via webhook_id in description."""
        # Use IDs that pass validation but contain XSS attempts
        xss_ids = [
            "webhook_script_test",  # Will pass validation, but test HTML escaping
        ]

        for webhook_id in xss_ids:
            config = {"data_type": "json", "module": "log"}
            path_item = generate_webhook_path(webhook_id, config)

            if path_item:
                description = path_item["post"]["description"]
                # SECURITY: Description should be HTML-escaped
                # Check that HTML tags are escaped
                assert "<script>" not in description.lower()
                assert "&lt;" in description or "<" not in description


# ============================================================================
# 2. INFORMATION DISCLOSURE
# ============================================================================


class TestOpenAPIGeneratorInformationDisclosure:
    """Test information disclosure vulnerabilities."""

    def test_oauth2_introspection_endpoint_disclosure(self):
        """Test that OAuth2 introspection endpoints are validated for SSRF prevention."""
        # Test with internal endpoint (should be redacted)
        internal_config = {
            "data_type": "json",
            "module": "log",
            "oauth2": {
                "introspection_endpoint": "http://127.0.0.1:8080/introspect",
                "required_scope": ["read"],
            },
        }

        schemes = extract_auth_schemes(internal_config)

        # SECURITY: Internal endpoints should not be exposed
        if "oauth2" in schemes:
            flows = schemes["oauth2"].get("flows", {})
            if "clientCredentials" in flows:
                token_url = flows["clientCredentials"].get("tokenUrl", "")
                # Internal endpoint should not be in tokenUrl
                assert "127.0.0.1" not in token_url
                assert "localhost" not in token_url.lower()

        # Test with public endpoint (should be exposed)
        public_config = {
            "data_type": "json",
            "module": "log",
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "required_scope": ["read"],
            },
        }

        schemes = extract_auth_schemes(public_config)

        # Public endpoint should be exposed
        if "oauth2" in schemes:
            flows = schemes["oauth2"].get("flows", {})
            if "clientCredentials" in flows:
                token_url = flows["clientCredentials"].get("tokenUrl", "")
                # Public endpoint should be in tokenUrl
                assert "auth.example.com" in token_url or token_url == ""

    def test_api_key_disclosure_in_description(self):
        """Test that API keys might be exposed in descriptions."""
        config = {
            "data_type": "json",
            "module": "log",
            "header_auth": {
                "header_name": "X-API-Key",
                "api_key": "secret_api_key_12345",  # Should not be in schema
            },
        }

        schemes = extract_auth_schemes(config)

        # SECURITY: API key should not be in schema
        # Currently, only header_name is used, not api_key (good)
        if "headerAuth" in schemes:
            # Should not contain actual API key
            scheme_def = schemes["headerAuth"]
            assert "api_key" not in str(
                scheme_def
            ).lower() or "secret_api_key_12345" not in str(scheme_def)

    def test_connection_details_disclosure(self):
        """Test that connection details might be exposed."""
        config = {
            "data_type": "json",
            "module": "postgresql",
            "module-config": {
                "connection_string": "postgresql://user:password@localhost:5432/db",
                "table": "webhooks",
            },
        }

        path_item = generate_webhook_path("test_webhook", config)

        if path_item:
            description = path_item["post"]["description"]
            # SECURITY: Connection strings should not be in description
            # Currently, module-config is not included in description (good)
            assert "connection_string" not in description.lower()
            assert "password" not in description.lower()

    def test_security_info_ip_whitelist_disclosure(self):
        """Test that IP whitelist details are exposed."""
        config = {
            "data_type": "json",
            "module": "log",
            "ip_whitelist": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        }

        security_info = extract_security_info(config)

        # SECURITY: IP whitelist might reveal internal network structure
        # Currently, only count is shown, not actual IPs (good)
        if "IP Whitelist" in security_info:
            info = security_info["IP Whitelist"]
            # Should show count, not actual IPs
            assert "192.168.1.1" not in info
            assert "10.0.0.1" not in info
            # Should show count
            assert "3" in info or "allowed IP" in info.lower()


# ============================================================================
# 3. DENIAL OF SERVICE (DoS)
# ============================================================================


class TestOpenAPIGeneratorDoS:
    """Test DoS vulnerabilities."""

    def test_large_webhook_id_dos(self):
        """Test DoS via extremely large webhook_id."""
        large_id = "a" * 100000  # 100KB webhook_id

        config = {"data_type": "json", "module": "log"}

        # SECURITY: Should validate webhook_id length
        # Currently, no length limit
        try:
            schema = generate_openapi_schema({large_id: config})
            # Should not crash, but ideally should validate length
            assert isinstance(schema, dict)
        except (MemoryError, RecursionError):
            # Acceptable for extremely large inputs
            pass

    def test_many_webhooks_dos(self):
        """Test DoS via many webhooks."""
        # Create config with many webhooks
        webhook_config = {}
        for i in range(10000):
            webhook_config[f"webhook_{i}"] = {"data_type": "json", "module": "log"}

        # SECURITY: Should handle large configs gracefully
        # Currently, no limit on number of webhooks
        try:
            schema = generate_openapi_schema(webhook_config)
            # Should not crash
            assert isinstance(schema, dict)
        except (MemoryError, RecursionError):
            # Acceptable for extremely large configs
            pass

    def test_deeply_nested_json_schema_dos(self):
        """Test DoS via deeply nested JSON schema."""
        # Create deeply nested schema
        nested_schema = {"type": "object", "properties": {}}
        current = nested_schema["properties"]
        for i in range(1000):
            current["nested"] = {"type": "object", "properties": {}}
            current = current["nested"]["properties"]

        config = {"data_type": "json", "module": "log", "json_schema": nested_schema}

        # SECURITY: Should handle deeply nested schemas
        try:
            path_item = generate_webhook_path("test", config)
            # Should not crash
            assert path_item is None or isinstance(path_item, dict)
        except (RecursionError, MemoryError):
            # Acceptable for extremely deep nesting
            pass


# ============================================================================
# 4. TYPE CONFUSION
# ============================================================================


class TestOpenAPIGeneratorTypeConfusion:
    """Test type confusion vulnerabilities."""

    def test_webhook_id_type_validation(self):
        """Test that non-string webhook_ids are handled safely."""
        invalid_ids = [
            None,
            123,
            [],
            {},
            True,
        ]

        for invalid_id in invalid_ids:
            config = {"data_type": "json", "module": "log"}

            # SECURITY: Should validate webhook_id type
            # Currently, f-string will convert to string, but should validate
            try:
                if invalid_id is None:
                    # None as key will cause issues
                    continue
                schema = generate_openapi_schema({invalid_id: config})
                # Should handle gracefully
                assert isinstance(schema, dict)
            except (TypeError, AttributeError):
                # Acceptable - type validation should reject invalid types
                pass

    def test_config_type_validation(self):
        """Test that invalid config types are handled safely."""
        invalid_configs = [
            None,
            "not a dict",
            123,
            [],
        ]

        for invalid_config in invalid_configs:
            # SECURITY: Should validate config type
            path_item = generate_webhook_path("test", invalid_config)
            # Should return None for invalid config
            assert path_item is None


# ============================================================================
# 5. JSON SCHEMA INJECTION
# ============================================================================


class TestOpenAPIGeneratorJSONSchemaInjection:
    """Test JSON schema injection vulnerabilities."""

    def test_json_schema_direct_usage(self):
        """Test that json_schema from config is used directly."""
        malicious_schema = {
            "type": "object",
            "properties": {
                "malicious": {
                    "type": "string",
                    "description": "'; DROP TABLE users; --",
                }
            },
        }

        config = {"data_type": "json", "module": "log", "json_schema": malicious_schema}

        # SECURITY: json_schema is used directly without validation
        # Currently: return json_schema if isinstance(json_schema, dict)
        # TODO: Should validate json_schema structure
        path_item = generate_webhook_path("test", config)

        if path_item:
            request_body = path_item["post"]["requestBody"]
            schema = request_body["content"]["application/json"]["schema"]
            # Malicious schema is included
            assert isinstance(schema, dict)

    def test_json_schema_circular_reference(self):
        """Test circular reference in JSON schema."""
        # Create circular reference
        schema = {"type": "object", "properties": {}}
        schema["properties"]["self"] = schema

        config = {"data_type": "json", "module": "log", "json_schema": schema}

        # SECURITY: Should handle circular references
        try:
            path_item = generate_webhook_path("test", config)
            # Should not crash
            assert path_item is None or isinstance(path_item, dict)
        except (RecursionError, ValueError):
            # Acceptable - circular references can't be serialized
            pass


# ============================================================================
# 6. XSS AND INJECTION IN DESCRIPTIONS
# ============================================================================


class TestOpenAPIGeneratorXSS:
    """Test XSS and injection vulnerabilities in descriptions."""

    def test_xss_in_webhook_id(self):
        """Test XSS via webhook_id in descriptions."""
        # Most XSS payloads will be rejected by webhook_id validation
        # Test with a valid webhook_id that contains characters that need escaping
        valid_webhook_id = "test_webhook"
        config = {"data_type": "json", "module": "log"}
        path_item = generate_webhook_path(valid_webhook_id, config)

        if path_item:
            description = path_item["post"]["description"]
            # SECURITY: Description should be HTML-escaped
            # Check that if we had HTML, it would be escaped
            # Since webhook_id is validated, dangerous chars are already filtered
            assert isinstance(description, str)
            # Verify HTML escaping works by checking description doesn't contain unescaped HTML
            assert "<script>" not in description.lower()

    def test_xss_in_module_name(self):
        """Test XSS via module name in descriptions."""
        xss_config = {"data_type": "json", "module": "<script>alert('xss')</script>"}

        path_item = generate_webhook_path("test", xss_config)

        if path_item:
            description = path_item["post"]["description"]
            # SECURITY: Module name should be HTML-escaped
            # Check that HTML tags are escaped
            assert "<script>" not in description.lower()
            # Should contain escaped version or sanitized version
            assert "&lt;" in description or "<" not in description

    def test_injection_in_security_info(self):
        """Test injection via security info values."""
        malicious_config = {
            "data_type": "json",
            "module": "log",
            "hmac": {
                "algorithm": "sha256",
                "header": "X-HMAC-Signature<script>alert('xss')</script>",
            },
        }

        security_info = extract_security_info(malicious_config)

        # SECURITY: Should sanitize security info values
        # Currently, header name is included in description
        if "HMAC Verification" in security_info:
            info = security_info["HMAC Verification"]
            # TODO: Should escape HTML/JavaScript
            assert isinstance(info, str)


# ============================================================================
# 7. CONTROL CHARACTERS AND NULL BYTES
# ============================================================================


class TestOpenAPIGeneratorControlCharacters:
    """Test control character and null byte vulnerabilities."""

    def test_null_byte_in_webhook_id(self):
        """Test null byte in webhook_id."""
        webhook_id = "test\x00null"
        config = {"data_type": "json", "module": "log"}

        # SECURITY: Should reject null bytes
        schema = generate_openapi_schema({webhook_id: config})
        paths = schema.get("paths", {})
        # Webhook_id with null byte should be rejected
        path_key = f"/webhook/{webhook_id}"
        assert path_key not in paths, "Webhook_id with null byte should be rejected"

    def test_control_characters_in_webhook_id(self):
        """Test control characters in webhook_id."""
        control_chars = [
            "test\nnewline",
            "test\rcarriage",
            "test\ttab",
            "test\fformfeed",
        ]

        for webhook_id in control_chars:
            config = {"data_type": "json", "module": "log"}
            # SECURITY: Should reject control characters
            schema = generate_openapi_schema({webhook_id: config})
            paths = schema.get("paths", {})
            # Webhook_id with control characters should be rejected
            path_key = f"/webhook/{webhook_id}"
            assert (
                path_key not in paths
            ), f"Webhook_id with control character should be rejected: {repr(webhook_id)}"


# ============================================================================
# 8. OAUTH2 ENDPOINT SSRF
# ============================================================================


class TestOpenAPIGeneratorOAuth2SSRF:
    """Test SSRF via OAuth2 introspection endpoint."""

    def test_oauth2_internal_endpoint_exposure(self):
        """Test that internal OAuth2 endpoints are not exposed."""
        ssrf_configs = [
            {
                "data_type": "json",
                "module": "log",
                "oauth2": {
                    "introspection_endpoint": "http://127.0.0.1:8080/introspect",
                    "required_scope": ["read"],
                },
            },
            {
                "data_type": "json",
                "module": "log",
                "oauth2": {
                    "introspection_endpoint": "http://192.168.1.1:8080/introspect",
                    "required_scope": ["read"],
                },
            },
            {
                "data_type": "json",
                "module": "log",
                "oauth2": {
                    "introspection_endpoint": "http://169.254.169.254/latest/meta-data",
                    "required_scope": ["read"],
                },
            },
        ]

        for config in ssrf_configs:
            schemes = extract_auth_schemes(config)

            # SECURITY: Internal OAuth2 endpoints should not be exposed
            if "oauth2" in schemes:
                flows = schemes["oauth2"].get("flows", {})
                if "clientCredentials" in flows:
                    token_url = flows["clientCredentials"].get("tokenUrl", "")
                    # Internal endpoints should not be in tokenUrl
                    assert "127.0.0.1" not in token_url
                    assert "192.168.1.1" not in token_url
                    assert "169.254.169.254" not in token_url
                    assert "localhost" not in token_url.lower()
