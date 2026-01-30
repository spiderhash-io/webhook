# JSON Schema Validation

Validate incoming webhook payloads against a JSON schema to ensure data structure compliance.

## Configuration

```json
{
    "validated_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer token",
        "json_schema": {
            "type": "object",
            "properties": {
                "event": {"type": "string"},
                "data": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"}
                    },
                    "required": ["id", "name"]
                }
            },
            "required": ["event", "data"]
        }
    }
}
```

## Schema Format

The `json_schema` field accepts a standard JSON Schema (Draft 7) definition:

- `type`: Data type (object, array, string, number, boolean, null)
- `properties`: Object properties definition
- `required`: Array of required property names
- `items`: Schema for array items
- `additionalProperties`: Whether to allow additional properties

## Example Schemas

### Simple Object

```json
{
    "json_schema": {
        "type": "object",
        "properties": {
            "event": {"type": "string"},
            "timestamp": {"type": "number"}
        },
        "required": ["event"]
    }
}
```

### Nested Object

```json
{
    "json_schema": {
        "type": "object",
        "properties": {
            "user": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "email": {"type": "string", "format": "email"}
                },
                "required": ["id", "email"]
            }
        },
        "required": ["user"]
    }
}
```

### Array Validation

```json
{
    "json_schema": {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "minItems": 1,
                "maxItems": 100
            }
        }
    }
}
```

## Error Response

When validation fails:

```json
{
    "error": "JSON schema validation failed",
    "detail": "Validation error details..."
}
```

HTTP Status: `400 Bad Request`

## Features

- Standard JSON Schema (Draft 7) support
- Nested object validation
- Array validation
- Type checking
- Required field validation
- Clear error messages
- SSRF protection (blocks remote schema references)

## Security

### SSRF Protection

Remote schema references (`$ref` with URLs) are blocked to prevent Server-Side Request Forgery attacks:

```json
// This will be blocked - remote $ref not allowed
{
    "json_schema": {
        "$ref": "https://malicious.com/schema.json"
    }
}
```

Only local/inline schema definitions are supported. If you need to reuse schemas, define them inline using `definitions`:

```json
{
    "json_schema": {
        "definitions": {
            "address": {
                "type": "object",
                "properties": {
                    "street": {"type": "string"},
                    "city": {"type": "string"}
                }
            }
        },
        "type": "object",
        "properties": {
            "shipping_address": {"$ref": "#/definitions/address"},
            "billing_address": {"$ref": "#/definitions/address"}
        }
    }
}
```

