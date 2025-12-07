"""Tests for OpenAPI schema generator."""
import pytest
from src.openapi_generator import (
    generate_openapi_schema,
    generate_webhook_path,
    extract_auth_schemes,
    extract_security_requirements,
    extract_request_body,
    extract_request_schema,
    extract_security_info,
    generate_responses
)


class TestOpenAPIGenerator:
    """Test OpenAPI schema generation."""
    
    def test_generate_openapi_schema_basic(self):
        """Test basic OpenAPI schema generation."""
        webhook_config = {
            "test_webhook": {
                "data_type": "json",
                "module": "log"
            }
        }
        
        schema = generate_openapi_schema(webhook_config)
        
        assert schema["openapi"] == "3.0.0"
        assert "info" in schema
        assert "paths" in schema
        assert "components" in schema
        assert "/webhook/test_webhook" in schema["paths"]
    
    def test_generate_openapi_schema_multiple_webhooks(self):
        """Test schema generation with multiple webhooks."""
        webhook_config = {
            "webhook1": {
                "data_type": "json",
                "module": "log"
            },
            "webhook2": {
                "data_type": "json",
                "module": "save_to_disk"
            }
        }
        
        schema = generate_openapi_schema(webhook_config)
        
        assert "/webhook/webhook1" in schema["paths"]
        assert "/webhook/webhook2" in schema["paths"]
        assert len(schema["paths"]) == 2
    
    def test_generate_webhook_path_basic(self):
        """Test webhook path generation."""
        config = {
            "data_type": "json",
            "module": "log"
        }
        
        path = generate_webhook_path("test_webhook", config)
        
        assert path is not None
        assert "post" in path
        assert path["post"]["operationId"] == "post_webhook_test_webhook"
        assert "parameters" in path["post"]
        assert "requestBody" in path["post"]
        assert "responses" in path["post"]
    
    def test_generate_webhook_path_invalid_config(self):
        """Test webhook path generation with invalid config."""
        # Non-dict config
        path = generate_webhook_path("test", "not a dict")
        assert path is None
        
        # Empty config
        path = generate_webhook_path("test", {})
        assert path is not None  # Should still generate a path
    
    def test_extract_auth_schemes_bearer(self):
        """Test extraction of Bearer token auth scheme."""
        config = {
            "authorization": "Bearer token123"
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "bearerAuth" in schemes
        assert schemes["bearerAuth"]["type"] == "http"
        assert schemes["bearerAuth"]["scheme"] == "bearer"
    
    def test_extract_auth_schemes_basic(self):
        """Test extraction of Basic auth scheme."""
        config = {
            "basic_auth": {
                "username": "user",
                "password": "pass"
            }
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "basicAuth" in schemes
        assert schemes["basicAuth"]["type"] == "http"
        assert schemes["basicAuth"]["scheme"] == "basic"
    
    def test_extract_auth_schemes_jwt(self):
        """Test extraction of JWT auth scheme."""
        config = {
            "jwt": {
                "secret": "secret"
            }
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "jwtAuth" in schemes
        assert schemes["jwtAuth"]["type"] == "http"
        assert schemes["jwtAuth"]["scheme"] == "bearer"
    
    def test_extract_auth_schemes_oauth2(self):
        """Test extraction of OAuth2 auth scheme."""
        config = {
            "oauth2": {
                "introspection_endpoint": "https://auth.example.com/introspect",
                "required_scope": ["read", "write"]
            }
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "oauth2" in schemes
        assert schemes["oauth2"]["type"] == "oauth2"
        assert "flows" in schemes["oauth2"]
    
    def test_extract_auth_schemes_hmac(self):
        """Test extraction of HMAC auth scheme."""
        config = {
            "hmac": {
                "secret": "secret",
                "header": "X-HMAC-Signature",
                "algorithm": "sha256"
            }
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "hmacAuth" in schemes
        assert schemes["hmacAuth"]["type"] == "apiKey"
        assert schemes["hmacAuth"]["in"] == "header"
        assert schemes["hmacAuth"]["name"] == "X-HMAC-Signature"
    
    def test_extract_auth_schemes_header_auth(self):
        """Test extraction of header-based auth scheme."""
        config = {
            "header_auth": {
                "header_name": "X-API-Key",
                "api_key": "key123"
            }
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "headerAuth" in schemes
        assert schemes["headerAuth"]["type"] == "apiKey"
        assert schemes["headerAuth"]["in"] == "header"
        assert schemes["headerAuth"]["name"] == "X-API-Key"
    
    def test_extract_auth_schemes_query_auth(self):
        """Test extraction of query parameter auth scheme."""
        config = {
            "query_auth": {
                "parameter_name": "api_key",
                "api_key": "key123"
            }
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "queryAuth" in schemes
        assert schemes["queryAuth"]["type"] == "apiKey"
        assert schemes["queryAuth"]["in"] == "query"
        assert schemes["queryAuth"]["name"] == "api_key"
    
    def test_extract_auth_schemes_digest(self):
        """Test extraction of Digest auth scheme."""
        config = {
            "digest_auth": {
                "username": "user",
                "password": "pass"
            }
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "digestAuth" in schemes
        assert schemes["digestAuth"]["type"] == "http"
        assert schemes["digestAuth"]["scheme"] == "digest"
    
    def test_extract_auth_schemes_multiple(self):
        """Test extraction of multiple auth schemes."""
        config = {
            "authorization": "Bearer token",
            "hmac": {
                "secret": "secret",
                "header": "X-HMAC-Signature"
            }
        }
        
        schemes = extract_auth_schemes(config)
        
        assert "bearerAuth" in schemes
        assert "hmacAuth" in schemes
    
    def test_extract_security_requirements(self):
        """Test extraction of security requirements."""
        config = {
            "authorization": "Bearer token"
        }
        
        security = extract_security_requirements(config)
        
        assert len(security) == 1
        assert "bearerAuth" in security[0]
    
    def test_extract_security_requirements_multiple(self):
        """Test extraction of multiple security requirements."""
        config = {
            "authorization": "Bearer token",
            "hmac": {
                "secret": "secret"
            }
        }
        
        security = extract_security_requirements(config)
        
        assert len(security) == 2
        assert any("bearerAuth" in req for req in security)
        assert any("hmacAuth" in req for req in security)
    
    def test_extract_security_requirements_none(self):
        """Test extraction with no security requirements."""
        config = {
            "data_type": "json",
            "module": "log"
        }
        
        security = extract_security_requirements(config)
        
        assert security == []
    
    def test_extract_request_body_json(self):
        """Test request body extraction for JSON."""
        config = {
            "data_type": "json"
        }
        
        request_body = extract_request_body(config)
        
        assert request_body["required"] is True
        assert "application/json" in request_body["content"]
    
    def test_extract_request_body_blob(self):
        """Test request body extraction for blob."""
        config = {
            "data_type": "blob"
        }
        
        request_body = extract_request_body(config)
        
        assert request_body["required"] is True
        assert "application/octet-stream" in request_body["content"]
    
    def test_extract_request_schema_with_json_schema(self):
        """Test request schema extraction with json_schema."""
        config = {
            "data_type": "json",
            "json_schema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "age": {"type": "integer"}
                },
                "required": ["name"]
            }
        }
        
        schema = extract_request_schema(config)
        
        assert schema["type"] == "object"
        assert "properties" in schema
        assert "name" in schema["properties"]
    
    def test_extract_request_schema_without_json_schema(self):
        """Test request schema extraction without json_schema."""
        config = {
            "data_type": "json"
        }
        
        schema = extract_request_schema(config)
        
        assert schema["type"] == "object"
        assert "additionalProperties" in schema
    
    def test_extract_security_info_rate_limit(self):
        """Test security info extraction with rate limiting."""
        config = {
            "rate_limit": {
                "enabled": True,
                "max_requests": 10,
                "window_seconds": 60
            }
        }
        
        info = extract_security_info(config)
        
        assert "Rate Limiting" in info
        assert "10" in info["Rate Limiting"]
        assert "60" in info["Rate Limiting"]
    
    def test_extract_security_info_ip_whitelist(self):
        """Test security info extraction with IP whitelist."""
        config = {
            "ip_whitelist": ["192.168.1.1", "10.0.0.1"]
        }
        
        info = extract_security_info(config)
        
        assert "IP Whitelist" in info
        assert "2" in info["IP Whitelist"]
    
    def test_extract_security_info_hmac(self):
        """Test security info extraction with HMAC."""
        config = {
            "hmac": {
                "algorithm": "sha256",
                "header": "X-HMAC-Signature"
            }
        }
        
        info = extract_security_info(config)
        
        assert "HMAC Verification" in info
        assert "SHA256" in info["HMAC Verification"]
        assert "X-HMAC-Signature" in info["HMAC Verification"]
    
    def test_extract_security_info_recaptcha(self):
        """Test security info extraction with reCAPTCHA."""
        config = {
            "recaptcha": {
                "version": "v3",
                "min_score": 0.5
            }
        }
        
        info = extract_security_info(config)
        
        assert "reCAPTCHA" in info
        assert "v3" in info["reCAPTCHA"]
        assert "0.5" in info["reCAPTCHA"]
    
    def test_extract_security_info_credential_cleanup(self):
        """Test security info extraction with credential cleanup."""
        config = {
            "credential_cleanup": {
                "enabled": True,
                "mode": "mask"
            }
        }
        
        info = extract_security_info(config)
        
        assert "Credential Cleanup" in info
        assert "mask" in info["Credential Cleanup"]
    
    def test_extract_security_info_json_schema(self):
        """Test security info extraction with JSON schema validation."""
        config = {
            "json_schema": {
                "type": "object"
            }
        }
        
        info = extract_security_info(config)
        
        assert "JSON Schema Validation" in info
    
    def test_extract_security_info_multiple(self):
        """Test security info extraction with multiple features."""
        config = {
            "rate_limit": {
                "enabled": True,
                "max_requests": 5,
                "window_seconds": 60
            },
            "ip_whitelist": ["192.168.1.1"],
            "json_schema": {
                "type": "object"
            }
        }
        
        info = extract_security_info(config)
        
        assert "Rate Limiting" in info
        assert "IP Whitelist" in info
        assert "JSON Schema Validation" in info
    
    def test_generate_responses(self):
        """Test response generation."""
        responses = generate_responses()
        
        assert "200" in responses
        assert "400" in responses
        assert "401" in responses
        assert "403" in responses
        assert "413" in responses
        assert "415" in responses
        assert "500" in responses
        
        # Check 200 response structure
        assert responses["200"]["description"] == "Webhook processed successfully"
        assert "content" in responses["200"]
    
    def test_generate_openapi_schema_with_auth(self):
        """Test OpenAPI schema generation with authentication."""
        webhook_config = {
            "secure_webhook": {
                "data_type": "json",
                "module": "log",
                "authorization": "Bearer token123",
                "hmac": {
                    "secret": "secret",
                    "header": "X-HMAC-Signature"
                }
            }
        }
        
        schema = generate_openapi_schema(webhook_config)
        
        assert "components" in schema
        assert "securitySchemes" in schema["components"]
        assert "bearerAuth" in schema["components"]["securitySchemes"]
        assert "hmacAuth" in schema["components"]["securitySchemes"]
        
        # Check path has security requirements
        path = schema["paths"]["/webhook/secure_webhook"]
        assert "security" in path["post"]
    
    def test_generate_openapi_schema_with_json_schema(self):
        """Test OpenAPI schema generation with JSON schema."""
        webhook_config = {
            "validated_webhook": {
                "data_type": "json",
                "module": "log",
                "json_schema": {
                    "type": "object",
                    "properties": {
                        "event": {"type": "string"},
                        "data": {"type": "object"}
                    },
                    "required": ["event"]
                }
            }
        }
        
        schema = generate_openapi_schema(webhook_config)
        
        path = schema["paths"]["/webhook/validated_webhook"]
        request_body = path["post"]["requestBody"]
        schema_def = request_body["content"]["application/json"]["schema"]
        
        assert schema_def["type"] == "object"
        assert "properties" in schema_def
        assert "event" in schema_def["properties"]
    
    def test_generate_openapi_schema_empty_config(self):
        """Test OpenAPI schema generation with empty config."""
        webhook_config = {}
        
        schema = generate_openapi_schema(webhook_config)
        
        assert schema["openapi"] == "3.0.0"
        assert schema["paths"] == {}
    
    def test_generate_openapi_schema_complex(self):
        """Test OpenAPI schema generation with complex webhook config."""
        webhook_config = {
            "complex_webhook": {
                "data_type": "json",
                "module": "postgresql",
                "authorization": "Bearer token",
                "rate_limit": {
                    "enabled": True,
                    "max_requests": 100,
                    "window_seconds": 3600
                },
                "ip_whitelist": ["192.168.1.0/24"],
                "json_schema": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"}
                    }
                },
                "credential_cleanup": {
                    "enabled": True,
                    "mode": "mask"
                }
            }
        }
        
        schema = generate_openapi_schema(webhook_config)
        
        assert "/webhook/complex_webhook" in schema["paths"]
        path = schema["paths"]["/webhook/complex_webhook"]
        
        # Check description includes security features
        description = path["post"]["description"]
        assert "Rate Limiting" in description
        assert "IP Whitelist" in description
        assert "JSON Schema Validation" in description
        assert "Credential Cleanup" in description

