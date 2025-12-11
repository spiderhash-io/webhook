"""
OpenAPI Schema Generator

Generates OpenAPI 3.0 documentation dynamically from webhooks.json configuration.
"""
from typing import Dict, List, Any, Optional
import json
import re
import html
import ipaddress
from urllib.parse import urlparse


def _validate_webhook_id(webhook_id: Any) -> Optional[str]:
    """
    Validate and sanitize webhook_id to prevent injection attacks and DoS.
    
    Args:
        webhook_id: The webhook identifier to validate
        
    Returns:
        Validated webhook_id string or None if invalid
        
    Raises:
        ValueError: If webhook_id is invalid or contains dangerous characters
    """
    if not webhook_id or not isinstance(webhook_id, str):
        return None
    
    webhook_id = webhook_id.strip()
    
    if not webhook_id:
        return None
    
    # Maximum length to prevent DoS (256 chars is reasonable for identifiers)
    MAX_WEBHOOK_ID_LENGTH = 256
    if len(webhook_id) > MAX_WEBHOOK_ID_LENGTH:
        return None
    
    # Reject null bytes and control characters (including tab, formfeed, etc.)
    # Control characters are 0x00-0x1F and 0x7F
    if '\x00' in webhook_id:
        return None
    
    # Check for control characters (excluding space 0x20)
    for char in webhook_id:
        if ord(char) < 32 or ord(char) == 127:
            return None
    
    # Reject dangerous characters that could be used in path injection
    dangerous_chars = [';', '|', '&', '$', '`', '\\', '/', '(', ')', '<', '>', '?', '*', '!', '{', '}', '[', ']']
    for char in dangerous_chars:
        if char in webhook_id:
            return None
    
    # Reject path traversal patterns
    if '..' in webhook_id or webhook_id.startswith('/') or webhook_id.startswith('\\'):
        return None
    
    return webhook_id


def _sanitize_for_description(text: str) -> str:
    """
    Sanitize text for use in OpenAPI descriptions to prevent XSS.
    
    Args:
        text: Text to sanitize
        
    Returns:
        HTML-escaped text safe for OpenAPI descriptions
    """
    if not isinstance(text, str):
        return str(text)
    
    # HTML escape to prevent XSS
    sanitized = html.escape(text)
    
    # Replace control characters with safe representations
    sanitized = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', sanitized)
    
    return sanitized


def _validate_oauth2_endpoint(endpoint: str) -> bool:
    """
    Validate OAuth2 introspection endpoint to prevent SSRF information disclosure.
    
    Args:
        endpoint: OAuth2 introspection endpoint URL
        
    Returns:
        True if endpoint is safe to expose, False otherwise
    """
    if not endpoint or not isinstance(endpoint, str):
        return False
    
    try:
        parsed = urlparse(endpoint)
        host = parsed.hostname
        
        if not host:
            return False
        
        # Block private IP ranges (RFC 1918)
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
        except ValueError:
            # Not an IP address, check hostname
            # Block localhost variants
            if host.lower() in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
                return False
            
            # Block cloud metadata service hostnames
            metadata_hostnames = [
                '169.254.169.254',  # AWS, GCP, Azure metadata
                'metadata.google.internal',
                'metadata.azure.com',
                'instance-data',
                'instance-data.ecs',
                'ecs-metadata',
                '100.100.100.200',  # Azure IMDS
            ]
            if host.lower() in metadata_hostnames:
                return False
        
        # Only allow http and https schemes
        if parsed.scheme.lower() not in ['http', 'https']:
            return False
        
        return True
    except Exception:
        return False


def generate_openapi_schema(webhook_config_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate complete OpenAPI 3.0 schema from webhook configurations.
    
    Args:
        webhook_config_data: Dictionary of webhook configurations from webhooks.json
        
    Returns:
        Complete OpenAPI 3.0 schema dictionary
    """
    # Base OpenAPI schema structure
    openapi_schema = {
        "openapi": "3.0.0",
        "info": {
            "title": "Core Webhook Module API",
            "version": "1.0.0",
            "description": "Dynamic webhook API documentation generated from configuration. "
                          "Each webhook endpoint accepts POST requests with JSON or blob payloads."
        },
        "servers": [
            {
                "url": "/",
                "description": "Current server"
            }
        ],
        "paths": {},
        "components": {
            "securitySchemes": {},
            "schemas": {}
        }
    }
    
    # Generate paths for each webhook
    paths = {}
    security_schemes = {}
    
    for webhook_id, config in webhook_config_data.items():
        # SECURITY: Validate webhook_id to prevent injection attacks
        validated_webhook_id = _validate_webhook_id(webhook_id)
        if not validated_webhook_id:
            # Skip invalid webhook_ids
            continue
        
        path_item = generate_webhook_path(validated_webhook_id, config)
        if path_item:
            paths[f"/webhook/{validated_webhook_id}"] = path_item
            
            # Extract and add security schemes
            schemes = extract_auth_schemes(config)
            for scheme_name, scheme_def in schemes.items():
                if scheme_name not in security_schemes:
                    security_schemes[scheme_name] = scheme_def
    
    openapi_schema["paths"] = paths
    openapi_schema["components"]["securitySchemes"] = security_schemes
    
    return openapi_schema


def generate_webhook_path(webhook_id: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Generate OpenAPI path item for a single webhook.
    
    Args:
        webhook_id: Webhook identifier
        config: Webhook configuration dictionary
        
    Returns:
        OpenAPI path item dictionary or None if invalid
    """
    if not isinstance(config, dict):
        return None
    
    data_type = config.get("data_type", "json")
    
    # SECURITY: Sanitize webhook_id and module for descriptions to prevent XSS
    sanitized_webhook_id = _sanitize_for_description(webhook_id)
    
    # Build description
    description_parts = []
    description_parts.append(f"Webhook endpoint: {sanitized_webhook_id}")
    
    module = config.get("module", "unknown")
    sanitized_module = _sanitize_for_description(str(module))
    description_parts.append(f"Module: {sanitized_module}")
    
    # Add security features to description
    security_info = extract_security_info(config)
    if security_info:
        description_parts.append("\n**Security Features:**")
        for feature, value in security_info.items():
            # SECURITY: Sanitize security info values to prevent XSS
            sanitized_feature = _sanitize_for_description(feature)
            sanitized_value = _sanitize_for_description(str(value))
            description_parts.append(f"- {sanitized_feature}: {sanitized_value}")
    
    # SECURITY: Sanitize webhook_id in operationId (alphanumeric + underscore only)
    # Remove any remaining dangerous characters
    safe_operation_id = re.sub(r'[^a-zA-Z0-9_]', '_', webhook_id)
    if not safe_operation_id or not safe_operation_id[0].isalpha():
        safe_operation_id = f"webhook_{safe_operation_id}" if safe_operation_id else "webhook_unknown"
    operation_id = f"post_webhook_{safe_operation_id}"
    
    # Build path item
    path_item = {
        "post": {
            "tags": ["webhooks"],
            "summary": f"Send webhook to {sanitized_webhook_id}",
            "description": "\n".join(description_parts),
            "operationId": operation_id,
            "parameters": [
                {
                    "name": "webhook_id",
                    "in": "path",
                    "required": True,
                    "description": f"Webhook identifier: {sanitized_webhook_id}",
                    "schema": {
                        "type": "string",
                        "example": sanitized_webhook_id
                    }
                }
            ],
            "requestBody": extract_request_body(config),
            "responses": generate_responses(),
            "security": extract_security_requirements(config)
        }
    }
    
    return path_item


def extract_auth_schemes(config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Extract authentication schemes from webhook config and convert to OpenAPI security schemes.
    
    Args:
        config: Webhook configuration dictionary
        
    Returns:
        Dictionary of security scheme definitions
    """
    schemes = {}
    
    # Bearer token (authorization field)
    if config.get("authorization"):
        schemes["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Bearer token authentication"
        }
    
    # Basic Auth
    if config.get("basic_auth"):
        schemes["basicAuth"] = {
            "type": "http",
            "scheme": "basic",
            "description": "HTTP Basic Authentication"
        }
    
    # JWT
    if config.get("jwt"):
        schemes["jwtAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token authentication"
        }
    
    # OAuth2
    if config.get("oauth2"):
        oauth2_config = config.get("oauth2", {})
        flows = {}
        
        # Determine flow type (most webhooks use client credentials)
        if oauth2_config.get("introspection_endpoint"):
            introspection_endpoint = oauth2_config.get("introspection_endpoint", "")
            
            # SECURITY: Validate OAuth2 endpoint to prevent SSRF information disclosure
            # Only expose endpoints that are safe (not private IPs, localhost, etc.)
            if _validate_oauth2_endpoint(introspection_endpoint):
                flows["clientCredentials"] = {
                    "tokenUrl": introspection_endpoint,
                    "scopes": {}
                }
                # Add required scopes if specified
                required_scopes = oauth2_config.get("required_scope", [])
                if isinstance(required_scopes, list):
                    for scope in required_scopes:
                        # SECURITY: Sanitize scope names
                        sanitized_scope = _sanitize_for_description(str(scope))
                        flows["clientCredentials"]["scopes"][sanitized_scope] = f"Required scope: {sanitized_scope}"
            else:
                # Internal/private endpoint - don't expose in schema
                # Still add OAuth2 scheme but without tokenUrl
                flows["clientCredentials"] = {
                    "scopes": {}
                }
                # Add required scopes if specified
                required_scopes = oauth2_config.get("required_scope", [])
                if isinstance(required_scopes, list):
                    for scope in required_scopes:
                        sanitized_scope = _sanitize_for_description(str(scope))
                        flows["clientCredentials"]["scopes"][sanitized_scope] = f"Required scope: {sanitized_scope}"
        
        schemes["oauth2"] = {
            "type": "oauth2",
            "flows": flows,
            "description": "OAuth 2.0 authentication"
        }
    
    # OAuth1
    if config.get("oauth1"):
        schemes["oauth1"] = {
            "type": "oauth2",  # OpenAPI doesn't have OAuth1, use oauth2 as closest match
            "description": "OAuth 1.0 authentication"
        }
    
    # HMAC
    if config.get("hmac"):
        hmac_config = config.get("hmac", {})
        header_name = hmac_config.get("header", "X-HMAC-Signature")
        # SECURITY: Sanitize header name for description
        sanitized_header_name = _sanitize_for_description(str(header_name))
        schemes["hmacAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": header_name,  # Keep original for actual header name
            "description": f"HMAC signature authentication (header: {sanitized_header_name})"
        }
    
    # Header-based auth
    if config.get("header_auth"):
        header_auth_config = config.get("header_auth", {})
        header_name = header_auth_config.get("header_name", "X-API-Key")
        # SECURITY: Sanitize header name for description
        sanitized_header_name = _sanitize_for_description(str(header_name))
        schemes["headerAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": header_name,  # Keep original for actual header name
            "description": f"API key in header: {sanitized_header_name}"
        }
    
    # Query parameter auth
    if config.get("query_auth"):
        query_auth_config = config.get("query_auth", {})
        param_name = query_auth_config.get("parameter_name", "api_key")
        # SECURITY: Sanitize parameter name for description
        sanitized_param_name = _sanitize_for_description(str(param_name))
        schemes["queryAuth"] = {
            "type": "apiKey",
            "in": "query",
            "name": param_name,  # Keep original for actual parameter name
            "description": f"API key in query parameter: {sanitized_param_name}"
        }
    
    # Digest Auth
    if config.get("digest_auth"):
        schemes["digestAuth"] = {
            "type": "http",
            "scheme": "digest",
            "description": "HTTP Digest Authentication"
        }
    
    return schemes


def extract_security_requirements(config: Dict[str, Any]) -> List[Dict[str, List[str]]]:
    """
    Extract security requirements for a webhook endpoint.
    
    Args:
        config: Webhook configuration dictionary
        
    Returns:
        List of security requirement dictionaries
    """
    security = []
    
    # Bearer token
    if config.get("authorization"):
        security.append({"bearerAuth": []})
    
    # Basic Auth
    if config.get("basic_auth"):
        security.append({"basicAuth": []})
    
    # JWT
    if config.get("jwt"):
        security.append({"jwtAuth": []})
    
    # OAuth2
    if config.get("oauth2"):
        security.append({"oauth2": []})
    
    # OAuth1
    if config.get("oauth1"):
        security.append({"oauth1": []})
    
    # HMAC
    if config.get("hmac"):
        security.append({"hmacAuth": []})
    
    # Header auth
    if config.get("header_auth"):
        security.append({"headerAuth": []})
    
    # Query auth
    if config.get("query_auth"):
        security.append({"queryAuth": []})
    
    # Digest auth
    if config.get("digest_auth"):
        security.append({"digestAuth": []})
    
    # If no security specified, return empty list (no auth required)
    return security


def extract_request_body(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract request body schema from webhook config.
    
    Args:
        config: Webhook configuration dictionary
        
    Returns:
        OpenAPI request body dictionary
    """
    data_type = config.get("data_type", "json")
    
    request_body = {
        "required": True,
        "description": f"Webhook payload ({data_type} format)"
    }
    
    content = {}
    
    if data_type == "json":
        content["application/json"] = {
            "schema": extract_request_schema(config)
        }
    elif data_type == "blob":
        content["application/octet-stream"] = {
            "schema": {
                "type": "string",
                "format": "binary",
                "description": "Binary blob data"
            }
        }
    else:
        # Default to JSON
        content["application/json"] = {
            "schema": {
                "type": "object",
                "description": "JSON payload"
            }
        }
    
    request_body["content"] = content
    return request_body


def extract_request_schema(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract request body schema from webhook config.
    Uses json_schema if available, otherwise generates a generic schema.
    
    Args:
        config: Webhook configuration dictionary
        
    Returns:
        OpenAPI schema dictionary
    """
    # If json_schema is provided, use it (it's already in JSON Schema format, compatible with OpenAPI)
    if "json_schema" in config:
        json_schema = config.get("json_schema")
        if isinstance(json_schema, dict):
            # SECURITY: Validate JSON schema structure to prevent injection
            # Basic validation - check for circular references
            try:
                # Try to serialize to check for circular references
                # Use a custom function to limit depth
                def _check_schema_depth(obj, depth=0, visited=None):
                    if visited is None:
                        visited = set()
                    if depth > 20:  # Limit depth to prevent DoS
                        raise RecursionError("Schema too deeply nested")
                    obj_id = id(obj)
                    if obj_id in visited:
                        raise ValueError("Circular reference detected")
                    if isinstance(obj, dict):
                        visited.add(obj_id)
                        for value in obj.values():
                            _check_schema_depth(value, depth + 1, visited)
                        visited.discard(obj_id)
                    elif isinstance(obj, list):
                        visited.add(obj_id)
                        for item in obj:
                            _check_schema_depth(item, depth + 1, visited)
                        visited.discard(obj_id)
                
                _check_schema_depth(json_schema)
                # Also try to serialize to ensure it's valid JSON
                json.dumps(json_schema)
                # JSON Schema is compatible with OpenAPI Schema
                return json_schema
            except (ValueError, RecursionError, TypeError):
                # Invalid schema (circular reference or too deep) - use generic schema
                pass
    
    # Otherwise, generate a generic schema based on data_type
    data_type = config.get("data_type", "json")
    
    if data_type == "json":
        return {
            "type": "object",
            "description": "JSON payload",
            "additionalProperties": True
        }
    else:
        return {
            "type": "string",
            "format": "binary",
            "description": "Binary data"
        }


def extract_security_info(config: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract security features information from webhook config.
    
    Args:
        config: Webhook configuration dictionary
        
    Returns:
        Dictionary of security feature descriptions
    """
    info = {}
    
    # Rate limiting
    rate_limit = config.get("rate_limit", {})
    if rate_limit and rate_limit.get("enabled"):
        max_requests = rate_limit.get("max_requests", "N/A")
        window = rate_limit.get("window_seconds", "N/A")
        info["Rate Limiting"] = f"{max_requests} requests per {window} seconds"
    
    # IP Whitelist
    ip_whitelist = config.get("ip_whitelist")
    if ip_whitelist:
        if isinstance(ip_whitelist, list):
            count = len(ip_whitelist)
            info["IP Whitelist"] = f"{count} allowed IP address(es)"
        else:
            info["IP Whitelist"] = "Enabled"
    
    # HMAC
    if config.get("hmac"):
        hmac_config = config.get("hmac", {})
        algorithm = hmac_config.get("algorithm", "sha256")
        header = hmac_config.get("header", "X-HMAC-Signature")
        # SECURITY: Sanitize values to prevent XSS
        sanitized_algorithm = _sanitize_for_description(str(algorithm).upper())
        sanitized_header = _sanitize_for_description(str(header))
        info["HMAC Verification"] = f"{sanitized_algorithm} signature in {sanitized_header} header"
    
    # reCAPTCHA
    if config.get("recaptcha"):
        recaptcha_config = config.get("recaptcha", {})
        version = recaptcha_config.get("version", "v3")
        min_score = recaptcha_config.get("min_score")
        if min_score is not None:
            info["reCAPTCHA"] = f"{version} with minimum score {min_score}"
        else:
            info["reCAPTCHA"] = f"{version}"
    
    # Credential Cleanup
    credential_cleanup = config.get("credential_cleanup", {})
    if credential_cleanup and credential_cleanup.get("enabled"):
        mode = credential_cleanup.get("mode", "mask")
        info["Credential Cleanup"] = f"Enabled ({mode} mode)"
    
    # JSON Schema Validation
    if config.get("json_schema"):
        info["JSON Schema Validation"] = "Enabled"
    
    return info


def generate_responses() -> Dict[str, Any]:
    """
    Generate standard response schemas for webhook endpoints.
    
    Returns:
        Dictionary of response definitions
    """
    return {
        "200": {
            "description": "Webhook processed successfully",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "example": "200 OK"
                            }
                        }
                    }
                }
            }
        },
        "400": {
            "description": "Bad Request - Invalid payload or validation error",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "example": "Invalid JSON payload"
                            }
                        }
                    }
                }
            }
        },
        "401": {
            "description": "Unauthorized - Authentication failed",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "example": "Invalid authentication credentials"
                            }
                        }
                    }
                }
            }
        },
        "403": {
            "description": "Forbidden - IP whitelist violation or rate limit exceeded",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "example": "Access denied"
                            }
                        }
                    }
                }
            }
        },
        "413": {
            "description": "Payload Too Large - Request payload exceeds size limit",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "example": "Payload size exceeds limit"
                            }
                        }
                    }
                }
            }
        },
        "415": {
            "description": "Unsupported Media Type - Invalid data type",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "example": "Unsupported data type"
                            }
                        }
                    }
                }
            }
        },
        "500": {
            "description": "Internal Server Error",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "example": "Internal server error"
                            }
                        }
                    }
                }
            }
        }
    }

