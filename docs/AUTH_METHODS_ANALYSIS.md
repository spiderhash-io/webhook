# Authentication Methods Analysis

## Current Implementation Status

### ✅ Implemented Authentication Methods

1. **Basic Auth** ✅
   - Class: `BasicAuthValidator`
   - Location: `src/validators.py`
   - Config: `basic_auth: { username, password }`
   - Status: Fully implemented with constant-time comparison

2. **Bearer Auth** ✅
   - Class: `AuthorizationValidator`
   - Location: `src/validators.py`
   - Config: `authorization: "Bearer {token}"`
   - Status: Implemented (simple Bearer token validation)

3. **Custom Auth** ✅
   - Class: `AuthorizationValidator`
   - Location: `src/validators.py`
   - Config: `authorization: "Custom {value}"`
   - Status: Supports any custom authorization header format

4. **JWT (JSON Web Tokens)** ✅
   - Class: `JWTValidator`
   - Location: `src/validators.py`
   - Config: `jwt: { secret, algorithm, issuer, audience, verify_exp }`
   - Status: Fully implemented with PyJWT library

5. **HMAC Signature** ✅
   - Class: `HMACValidator`
   - Location: `src/validators.py`
   - Config: `hmac: { secret, header, algorithm }`
   - Status: Supports SHA1, SHA256, SHA512

6. **Header Auth (HMAC-based)** ✅
   - Class: `HMACValidator`
   - Location: `src/validators.py`
   - Config: Custom header with HMAC signature
   - Status: Implemented for HMAC, but not generic header auth

## ❌ Missing Authentication Methods

### 1. Digest Auth ❌
**Status**: Not implemented

**Description**: HTTP Digest Authentication (RFC 7616)
- Challenge-response authentication
- Uses MD5/SHA-256 hashing
- More secure than Basic Auth (no password transmission)

**Use Cases**:
- When Basic Auth is not secure enough
- Legacy systems requiring Digest Auth
- Webhook providers using Digest Auth

**Implementation Requirements**:
- Generate WWW-Authenticate challenge
- Validate Authorization header with digest response
- Support MD5 and SHA-256 algorithms
- Handle nonce, realm, qop parameters

**Config Example**:
```json
{
  "digest_auth": {
    "username": "user",
    "password": "pass",
    "realm": "Webhook API",
    "algorithm": "MD5",
    "qop": "auth"
  }
}
```

### 2. OAuth 1.0 ❌
**Status**: Not implemented

**Description**: OAuth 1.0 (RFC 5849)
- Three-legged OAuth flow
- Signature-based authentication
- Consumer key/secret, token/secret

**Use Cases**:
- Twitter API webhooks
- Legacy OAuth 1.0 providers
- Services still using OAuth 1.0

**Implementation Requirements**:
- Validate OAuth signature
- Check timestamp/nonce
- Support HMAC-SHA1, RSA-SHA1, PLAINTEXT
- Handle oauth_* parameters

**Config Example**:
```json
{
  "oauth1": {
    "consumer_key": "key",
    "consumer_secret": "secret",
    "signature_method": "HMAC-SHA1",
    "verify_timestamp": true,
    "timestamp_window": 300
  }
}
```

### 3. OAuth 2.0 ❌
**Status**: Not implemented

**Description**: OAuth 2.0 (RFC 6749)
- Token-based authentication
- Multiple grant types (client credentials, authorization code, etc.)
- Access token validation

**Use Cases**:
- Modern API authentication
- Third-party service integrations
- Standard OAuth 2.0 providers

**Implementation Requirements**:
- Validate access tokens
- Support token introspection endpoint
- Validate token scope
- Handle Bearer token format
- Support JWT access tokens

**Config Example**:
```json
{
  "oauth2": {
    "token_type": "Bearer",
    "introspection_endpoint": "https://auth.example.com/introspect",
    "client_id": "client_id",
    "client_secret": "client_secret",
    "required_scope": ["webhook:write"],
    "validate_token": true
  }
}
```

### 4. Query Parameter Auth ❌
**Status**: Not implemented

**Description**: API key authentication via query parameters
- Token/API key in URL query string
- Common pattern: `?api_key=xxx` or `?token=xxx`

**Use Cases**:
- Simple API key authentication
- Legacy webhook providers
- Services using query-based auth

**Implementation Requirements**:
- Extract token from query parameters
- Support multiple parameter names (api_key, token, key, etc.)
- Validate against configured key
- Constant-time comparison

**Config Example**:
```json
{
  "query_auth": {
    "parameter_name": "api_key",
    "api_key": "secret_key_123",
    "case_sensitive": false
  }
}
```

### 5. Generic Header Auth ❌
**Status**: Partially implemented (only HMAC)

**Description**: Custom header-based authentication
- API key in custom header (not Authorization)
- Common: `X-API-Key`, `X-Auth-Token`, etc.

**Use Cases**:
- Custom API key authentication
- Services using non-standard headers
- Header-based token validation

**Implementation Requirements**:
- Support custom header names
- Validate header value against configured key
- Support multiple header formats

**Config Example**:
```json
{
  "header_auth": {
    "header_name": "X-API-Key",
    "api_key": "secret_key_123",
    "case_sensitive": false
  }
}
```

## Implementation Priority

### High Priority
1. **Query Parameter Auth** - Simple, widely used, easy to implement
2. **Generic Header Auth** - Common pattern, straightforward
3. **OAuth 2.0** - Modern standard, high demand

### Medium Priority
4. **Digest Auth** - Less common but still used
5. **OAuth 1.0** - Legacy but still needed for some providers

## Implementation Plan

### Phase 1: Simple Auth Methods (1-2 days)
- Query Parameter Auth
- Generic Header Auth

### Phase 2: OAuth 2.0 (2-3 days)
- Access token validation
- Token introspection
- Scope validation

### Phase 3: Advanced Auth (2-3 days)
- Digest Auth
- OAuth 1.0

## Dependencies

### New Dependencies Required
- **OAuth 2.0**: May need `authlib` or `oauthlib` for token validation
- **Digest Auth**: Can use `httpx` or `requests` for challenge/response
- **OAuth 1.0**: May need `oauthlib` or custom implementation

### No New Dependencies
- Query Parameter Auth: Built-in
- Generic Header Auth: Built-in

## Testing Requirements

Each new auth method needs:
1. Unit tests (valid/invalid credentials)
2. Edge case tests (missing headers, malformed tokens)
3. Security tests (timing attacks, injection)
4. Integration tests (full webhook flow)

## Security Considerations

1. **Constant-time comparison** for all token/key comparisons
2. **No sensitive data in logs** (mask tokens/keys)
3. **Rate limiting** on auth failures
4. **Token expiration** validation where applicable
5. **Secure storage** of secrets (environment variables)

## Configuration Examples

### Complete Auth Config Example
```json
{
  "webhook_id": {
    "data_type": "json",
    "module": "log",
    
    "basic_auth": {
      "username": "user",
      "password": "pass"
    },
    
    "digest_auth": {
      "username": "user",
      "password": "pass",
      "realm": "Webhook API"
    },
    
    "authorization": "Bearer token",
    
    "jwt": {
      "secret": "jwt_secret",
      "algorithm": "HS256"
    },
    
    "oauth1": {
      "consumer_key": "key",
      "consumer_secret": "secret"
    },
    
    "oauth2": {
      "introspection_endpoint": "https://auth.example.com/introspect",
      "client_id": "client_id",
      "client_secret": "client_secret"
    },
    
    "query_auth": {
      "parameter_name": "api_key",
      "api_key": "secret_key"
    },
    
    "header_auth": {
      "header_name": "X-API-Key",
      "api_key": "secret_key"
    },
    
    "hmac": {
      "secret": "hmac_secret",
      "header": "X-HMAC-Signature",
      "algorithm": "sha256"
    }
  }
}
```

## Summary

**Currently Implemented**: 6 methods
- Basic Auth ✅
- Bearer Auth ✅
- Custom Auth ✅
- JWT ✅
- HMAC ✅
- Header Auth (HMAC) ✅

**Missing**: 5 methods
- Digest Auth ❌
- OAuth 1.0 ❌
- OAuth 2.0 ❌
- Query Parameter Auth ❌
- Generic Header Auth ❌

**Total Coverage**: 6/11 methods (54.5%)

