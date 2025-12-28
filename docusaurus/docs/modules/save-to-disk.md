# Save to Disk Module

The Save to Disk Module saves webhook payloads to the local filesystem.

## Configuration

```json
{
    "disk_webhook": {
        "data_type": "json",
        "module": "save_to_disk",
        "module-config": {
            "path": "webhooks/archive",
            "filename_pattern": "webhook_{timestamp}_{uuid}.json",
            "include_headers": true
        },
        "authorization": "Bearer token"
    }
}
```

## Module Configuration Options

- `path`: Directory path to save files (required)
- `filename_pattern`: Pattern for filenames (supports `{timestamp}`, `{uuid}`, `{webhook_id}`)
- `include_headers`: Whether to include HTTP headers in saved files (default: false)
- `file_extension`: File extension (default: ".json")

## Features

- Local file storage
- Configurable file naming patterns
- Automatic directory creation
- Support for JSON and blob data types
- Timestamp and UUID in filenames

