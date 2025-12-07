"""
OpenAPI Schema Generator

Generates OpenAPI 3.0 documentation dynamically from webhooks.json configuration.
"""
from typing import Dict, List, Any, Optional
import json


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
        path_item = generate_webhook_path(webhook_id, config)
        if path_item:
            paths[f"/webhook/{webhook_id}"] = path_item
            
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
    
    # Build description
    description_parts = []
    description_parts.append(f"Webhook endpoint: {webhook_id}")
    
    module = config.get("module", "unknown")
    description_parts.append(f"Module: {module}")
    
    # Add security features to description
    security_info = extract_security_info(config)
    if security_info:
        description_parts.append("\n**Security Features:**")
        for feature, value in security_info.items():
            description_parts.append(f"- {feature}: {value}")
    
    # Build path item
    path_item = {
        "post": {
            "tags": ["webhooks"],
            "summary": f"Send webhook to {webhook_id}",
            "description": "\n".join(description_parts),
            "operationId": f"post_webhook_{webhook_id}",
            "parameters": [
                {
                    "name": "webhook_id",
                    "in": "path",
                    "required": True,
                    "description": f"Webhook identifier: {webhook_id}",
                    "schema": {
                        "type": "string",
                        "example": webhook_id
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
            flows["clientCredentials"] = {
                "tokenUrl": oauth2_config.get("introspection_endpoint", ""),
                "scopes": {}
            }
            # Add required scopes if specified
            required_scopes = oauth2_config.get("required_scope", [])
            if isinstance(required_scopes, list):
                for scope in required_scopes:
                    flows["clientCredentials"]["scopes"][scope] = f"Required scope: {scope}"
        
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
        schemes["hmacAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": header_name,
            "description": f"HMAC signature authentication (header: {header_name})"
        }
    
    # Header-based auth
    if config.get("header_auth"):
        header_auth_config = config.get("header_auth", {})
        header_name = header_auth_config.get("header_name", "X-API-Key")
        schemes["headerAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": header_name,
            "description": f"API key in header: {header_name}"
        }
    
    # Query parameter auth
    if config.get("query_auth"):
        query_auth_config = config.get("query_auth", {})
        param_name = query_auth_config.get("parameter_name", "api_key")
        schemes["queryAuth"] = {
            "type": "apiKey",
            "in": "query",
            "name": param_name,
            "description": f"API key in query parameter: {param_name}"
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
            # JSON Schema is compatible with OpenAPI Schema
            return json_schema
    
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
        info["HMAC Verification"] = f"{algorithm.upper()} signature in {header} header"
    
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

