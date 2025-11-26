# Dynamic OpenAPI Documentation Analysis

## Overview

This document analyzes the implementation of dynamic OpenAPI documentation generation based on `webhooks.json` configuration. The goal is to automatically generate comprehensive API documentation for each configured webhook endpoint.

## Current State

### Existing OpenAPI Documentation

Currently, FastAPI automatically generates OpenAPI documentation, but it only shows:
- Generic `/webhook/{webhook_id}` endpoint
- No webhook-specific information
- No authentication requirements
- No validation rules
- No examples or schemas

**Current OpenAPI output:**
```json
{
  "/webhook/{webhook_id}": {
    "post": {
      "summary": "Read Webhook",
      "parameters": [
        {
          "name": "webhook_id",
          "in": "path",
          "required": true,
          "schema": {"type": "string"}
        }
      ],
      "responses": {
        "200": {"description": "Successful Response"}
      }
    }
  }
}
```

### Configuration Structure

From `webhooks.json`, each webhook can have:
- **Authentication**: `authorization`, `basic_auth`, `jwt`, `hmac`
- **Validation**: `ip_whitelist`, `rate_limit`, `json_schema`, `recaptcha`
- **Module**: `module` (log, rabbitmq, redis_rq, etc.)
- **Module Config**: `module-config` (module-specific settings)
- **Data Type**: `data_type` (json, form-data, etc.)
- **Retry**: `retry` configuration

## Design Options

### Option 1: Custom OpenAPI Schema Modification (Recommended)

**Approach**: Modify the OpenAPI schema at startup using FastAPI's `openapi_schema` customization.

**Pros:**
- Full control over documentation
- Can include all webhook-specific details
- Works with FastAPI's built-in Swagger UI
- Can add examples, schemas, and descriptions
- Supports all authentication methods

**Cons:**
- Requires manual schema construction
- More complex implementation
- Need to handle schema updates on config changes

**Implementation Steps:**
1. Create `src/openapi_generator.py` module
2. Read `webhooks.json` at startup
3. Generate OpenAPI paths for each webhook
4. Customize FastAPI app's OpenAPI schema
5. Include authentication, validation, and module information

### Option 2: Dynamic Route Registration

**Approach**: Dynamically register routes for each webhook with proper decorators.

**Pros:**
- FastAPI automatically generates docs
- Less manual schema work
- Natural integration

**Cons:**
- Harder to customize per-webhook details
- Limited control over documentation
- May not support all features (e.g., dynamic auth requirements)

### Option 3: OpenAPI Schema Extension

**Approach**: Use FastAPI's `openapi()` method to extend the schema.

**Pros:**
- Clean separation of concerns
- Easy to maintain
- Can add tags, descriptions, examples

**Cons:**
- Still requires manual path generation
- Similar complexity to Option 1

## Recommended Implementation (Option 1)

### Architecture

```
┌─────────────────────────────────────────┐
│         FastAPI Application              │
│  ┌──────────────────────────────────┐  │
│  │   OpenAPI Schema Generator        │  │
│  │   - Read webhooks.json            │  │
│  │   - Generate paths per webhook    │  │
│  │   - Add auth/validation info      │  │
│  └──────────────────────────────────┘  │
│              ↓                          │
│  ┌──────────────────────────────────┐  │
│  │   Custom OpenAPI Schema           │  │
│  │   - /webhook/{webhook_id} paths   │  │
│  │   - Security schemes              │  │
│  │   - Request/response schemas       │  │
│  └──────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Key Components

#### 1. OpenAPI Generator Module (`src/openapi_generator.py`)

```python
class OpenAPIGenerator:
    def __init__(self, webhook_config_data):
        self.webhook_config = webhook_config_data
    
    def generate_paths(self):
        """Generate OpenAPI paths for each webhook."""
        paths = {}
        for webhook_id, config in self.webhook_config.items():
            paths[f"/webhook/{webhook_id}"] = self._generate_webhook_path(
                webhook_id, config
            )
        return paths
    
    def _generate_webhook_path(self, webhook_id, config):
        """Generate OpenAPI path definition for a single webhook."""
        # Include:
        # - Summary and description
        # - Security requirements
        # - Request body schema
        # - Response schemas (200, 202, 400, 401, etc.)
        # - Examples
        pass
    
    def generate_security_schemes(self):
        """Generate security schemes based on webhook configs."""
        # Support:
        # - Bearer token (authorization)
        # - Basic Auth (basic_auth)
        # - JWT (jwt)
        # - HMAC (hmac)
        pass
```

#### 2. Schema Generation

For each webhook, generate:
- **Path Parameters**: `webhook_id` (already exists)
- **Security Requirements**: Based on auth config
- **Request Body**: JSON schema based on `json_schema` config or generic JSON
- **Response Schemas**: 
  - `200 OK`: Success response
  - `202 Accepted`: Retry in progress
  - `400 Bad Request`: Validation errors
  - `401 Unauthorized`: Auth failures
  - `413 Payload Too Large`: Size limits
  - `500 Internal Server Error`: Server errors

#### 3. Integration with FastAPI

```python
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    generator = OpenAPIGenerator(webhook_config_data)
    
    openapi_schema = get_openapi(
        title="Webhook API",
        version="1.0.0",
        description="Dynamic webhook endpoints",
        routes=app.routes,
    )
    
    # Add generated paths
    openapi_schema["paths"].update(generator.generate_paths())
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = (
        generator.generate_security_schemes()
    )
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
```

### Features to Document

#### 1. Authentication Methods

**Bearer Token:**
```yaml
security:
  - BearerAuth: []
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

**Basic Auth:**
```yaml
security:
  - BasicAuth: []
components:
  securitySchemes:
    BasicAuth:
      type: http
      scheme: basic
```

**JWT:**
```yaml
security:
  - JWTAuth: []
components:
  securitySchemes:
    JWTAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

**HMAC:**
```yaml
security:
  - HMACAuth: []
components:
  securitySchemes:
    HMACAuth:
      type: apiKey
      in: header
      name: X-HMAC-Signature
```

#### 2. Validation Rules

Document in description:
- IP whitelist requirements
- Rate limiting (requests per window)
- JSON schema validation
- Payload size limits
- reCAPTCHA requirements

#### 3. Module Information

Include in description:
- Destination module (log, rabbitmq, redis_rq, etc.)
- Module-specific configuration
- Retry configuration (if enabled)

#### 4. Request/Response Examples

```json
{
  "requestBody": {
    "content": {
      "application/json": {
        "schema": {
          "type": "object",
          "properties": {
            "event": {"type": "string"},
            "data": {"type": "object"}
          }
        },
        "examples": {
          "example1": {
            "value": {
              "event": "payment.completed",
              "data": {"amount": 100, "currency": "USD"}
            }
          }
        }
      }
    }
  }
}
```

### Example Generated Documentation

For a webhook with JWT auth and JSON schema:

```yaml
/webhook/payment_processor:
  post:
    summary: Payment Processor Webhook
    description: |
      Processes payment webhooks and forwards to RabbitMQ queue.
      
      **Authentication**: JWT token required
      **Validation**: JSON schema validation enabled
      **Rate Limit**: 100 requests per 60 seconds
      **Destination**: RabbitMQ queue 'payment_queue'
      **Retry**: Enabled (max 5 attempts)
    
    security:
      - JWTAuth: []
    
    parameters:
      - name: webhook_id
        in: path
        required: true
        schema:
          type: string
          example: payment_processor
    
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              event:
                type: string
              amount:
                type: number
              currency:
                type: string
            required: [event, amount]
          examples:
            payment_completed:
              value:
                event: "payment.completed"
                amount: 100.50
                currency: "USD"
    
    responses:
      '200':
        description: Webhook processed successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "200 OK"
                status:
                  type: string
                  example: "processed"
      
      '202':
        description: Webhook accepted, processing with retries
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "202 Accepted"
                status:
                  type: string
                  example: "accepted"
                note:
                  type: string
                  example: "Request accepted, processing in background"
      
      '400':
        description: Validation error (invalid payload, schema mismatch)
      
      '401':
        description: Authentication failed (invalid token, missing auth)
      
      '413':
        description: Payload too large
      
      '500':
        description: Internal server error
```

## Implementation Plan

### Phase 1: Basic Path Generation (MVP)
1. Create `OpenAPIGenerator` class
2. Generate basic paths for each webhook
3. Add webhook descriptions and summaries
4. Integrate with FastAPI's OpenAPI schema

### Phase 2: Authentication Documentation
1. Detect authentication methods from config
2. Generate security schemes
3. Add security requirements to paths
4. Document auth requirements in descriptions

### Phase 3: Validation Documentation
1. Document JSON schema validation
2. Document rate limiting
3. Document IP whitelist
4. Document payload size limits

### Phase 4: Advanced Features
1. Generate request/response examples
2. Include module-specific information
3. Document retry configuration
4. Add tags and categories

### Phase 5: Interactive Features
1. Add "Try it out" examples
2. Pre-fill authentication headers
3. Show validation rules in UI
4. Add webhook testing interface

## Technical Considerations

### 1. Schema Updates

**Challenge**: OpenAPI schema is generated at startup, but config may change.

**Solution**: 
- Regenerate schema on config reload (if implemented)
- Or document that schema updates require restart
- Consider adding `/reload-config` endpoint for development

### 2. Security Information

**Challenge**: Don't expose sensitive information (secrets, tokens) in docs.

**Solution**:
- Only show authentication method, not actual secrets
- Use placeholders: `Bearer {token}`
- Mark sensitive fields in descriptions

### 3. JSON Schema Integration

**Challenge**: Webhooks may have custom JSON schemas for validation.

**Solution**:
- Use the `json_schema` from webhook config
- Convert to OpenAPI schema format
- Include in request body documentation

### 4. Dynamic vs Static

**Challenge**: Balance between dynamic generation and performance.

**Solution**:
- Generate schema once at startup
- Cache the result
- Only regenerate if config changes

## Benefits

1. **Better Developer Experience**
   - Clear documentation for each webhook
   - Interactive testing via Swagger UI
   - Examples and schemas

2. **Reduced Support Burden**
   - Self-documenting API
   - Clear authentication requirements
   - Validation rules documented

3. **Easier Integration**
   - Clients can generate SDKs from OpenAPI
   - Clear request/response formats
   - Error handling documented

4. **Configuration-Driven**
   - Documentation automatically matches config
   - No manual doc updates needed
   - Single source of truth

## Testing Strategy

1. **Unit Tests**
   - Test path generation for different configs
   - Test security scheme generation
   - Test schema conversion

2. **Integration Tests**
   - Verify OpenAPI schema is valid
   - Check Swagger UI renders correctly
   - Test with different webhook configs

3. **Documentation Tests**
   - Verify all webhooks are documented
   - Check examples are valid
   - Ensure no sensitive data exposed

## Estimated Complexity

- **Implementation**: Medium (2-3 days)
- **Testing**: Medium (1 day)
- **Documentation**: Low (0.5 days)

**Total**: ~3-4 days

## Dependencies

No new dependencies required. Uses FastAPI's built-in OpenAPI support.

## Next Steps

1. Review and approve this design
2. Implement Phase 1 (basic path generation)
3. Test with existing webhook configs
4. Iterate based on feedback
5. Add advanced features incrementally

