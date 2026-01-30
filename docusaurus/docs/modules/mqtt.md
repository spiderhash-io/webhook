# MQTT Module

The MQTT Module publishes webhook payloads to MQTT brokers. Supports MQTT 3.1.1 and 5.0 protocols with TLS/SSL encryption.

## Configuration

```json
{
    "mqtt_events": {
        "data_type": "json",
        "module": "mqtt",
        "connection": "mqtt_local",
        "module-config": {
            "topic": "webhook/events",
            "qos": 1,
            "retained": false,
            "format": "json",
            "topic_prefix": "devices"
        },
        "authorization": "Bearer mqtt_secret"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "mqtt_local": {
        "type": "mqtt",
        "host": "localhost",
        "port": 1883,
        "username": "user",
        "password": "pass",
        "client_id": "webhook-module",
        "keepalive": 60,
        "mqtt_version": "3.1.1"
    }
}
```

### TLS/SSL Configuration

```json
{
    "mqtt_secure": {
        "type": "mqtt",
        "host": "mqtt.example.com",
        "port": 8883,
        "username": "user",
        "password": "pass",
        "tls": true,
        "tls_ca_cert_file": "/path/to/ca.crt",
        "tls_cert_file": "/path/to/client.crt",
        "tls_key_file": "/path/to/client.key",
        "tls_insecure": false
    }
}
```

## Connection Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | `"localhost"` | MQTT broker hostname |
| `port` | integer | `1883` | MQTT broker port |
| `username` | string | - | Authentication username |
| `password` | string | - | Authentication password |
| `client_id` | string | `"webhook-module"` | MQTT client identifier |
| `keepalive` | integer | `60` | Connection keepalive in seconds |
| `mqtt_version` | string | `"3.1.1"` | MQTT protocol version (`"3.1.1"` or `"5.0"`) |
| `tls` | boolean | `false` | Enable TLS/SSL |
| `tls_ca_cert_file` | string | - | CA certificate file path |
| `tls_cert_file` | string | - | Client certificate file path |
| `tls_key_file` | string | - | Client private key file path |
| `tls_insecure` | boolean | `false` | Allow self-signed certificates |

## Module Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `topic` | string | Required | MQTT topic to publish to |
| `qos` | integer | `1` | Quality of Service level (0, 1, or 2) |
| `retained` | boolean | `false` | Whether messages should be retained |
| `format` | string | `"json"` | Message format: `"json"` or `"raw"` |
| `topic_prefix` | string | - | Prefix prepended to topic |

## Topic Validation

Topic names are validated for security:

- Cannot contain wildcards (`+` or `#`) when publishing
- Cannot start with `$` (reserved for system topics)
- Cannot contain consecutive slashes (`//`)
- Maximum 32KB in length

## Special Features

### Shelly Device Compatibility

Supports Shelly Gen2/Gen3 JSON format:

```json
{
    "shelly_webhook": {
        "data_type": "json",
        "module": "mqtt",
        "connection": "mqtt_local",
        "module-config": {
            "topic": "shellies/device123/status",
            "shelly_gen2_format": true,
            "device_id": "device123",
            "qos": 1
        }
    }
}
```

### Sonoff/Tasmota Compatibility

Supports command (cmnd), status (stat), and telemetry (tele) topic formats:

```json
{
    "tasmota_webhook": {
        "data_type": "json",
        "module": "mqtt",
        "connection": "mqtt_local",
        "module-config": {
            "topic": "tasmota/device",
            "tasmota_format": true,
            "tasmota_type": "cmnd",
            "device_name": "switch1",
            "command": "POWER",
            "qos": 1
        }
    }
}
```

## Features

- MQTT 3.1.1 and 5.0 protocol support
- TLS/SSL encryption with client certificates
- QoS levels: 0, 1, 2
- Retained messages
- Topic prefix support
- Shelly and Tasmota device format support
- Topic name validation
