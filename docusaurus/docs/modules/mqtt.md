# MQTT Module

The MQTT Module publishes webhook payloads to MQTT brokers. Supports MQTT 3.1.1 and 5.0 protocols with TLS/SSL encryption.

## Configuration

```json
{
    "mqtt_events": {
        "data_type": "json",
        "module": "mqtt",
        "topic": "webhook/events",
        "connection": "mqtt_local",
        "module-config": {
            "qos": 1,
            "retained": false,
            "format": "json",
            "topic_prefix": "webhook"
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
        "tls": false,
        "ca_certs": "/path/to/ca.crt"
    }
}
```

## Module Configuration Options

- `qos`: Quality of Service level (0, 1, or 2, default: 1)
- `retained`: Whether messages should be retained (default: false)
- `format`: Message format - "json" or "raw" (default: "json")
- `topic_prefix`: Optional prefix for topic names

## Special Features

### Shelly Device Compatibility

Supports Shelly Gen1 (multi-topic) and Gen2/Gen3 (JSON format):

```json
{
    "shelly_webhook": {
        "data_type": "json",
        "module": "mqtt",
        "topic": "shellies/device123/status",
        "connection": "mqtt_shelly",
        "module-config": {
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
        "topic": "cmnd/device_name/POWER",
        "connection": "mqtt_sonoff",
        "module-config": {
            "tasmota_format": true,
            "tasmota_type": "cmnd",
            "device_name": "device_name",
            "command": "POWER",
            "qos": 1
        }
    }
}
```

## Features

- MQTT 3.1.1 and 5.0 protocol support
- TLS/SSL encryption (MQTTS)
- QoS levels: 0, 1, 2
- Retained messages
- Device-specific format support

