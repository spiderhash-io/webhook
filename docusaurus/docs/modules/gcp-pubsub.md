# GCP Pub/Sub Module

The GCP Pub/Sub Module publishes webhook payloads to Google Cloud Pub/Sub topics.

## Configuration

```json
{
    "gcp_pubsub_webhook": {
        "data_type": "json",
        "module": "gcp_pubsub",
        "connection": "gcp_pubsub_conn",
        "module-config": {
            "topic": "webhook-events",
            "project_id": "my-project"
        },
        "authorization": "Bearer token"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "gcp_pubsub_conn": {
        "type": "gcp_pubsub",
        "credentials_path": "/path/to/service-account.json",
        "project_id": "my-project"
    }
}
```

## Module Configuration Options

- `topic`: Pub/Sub topic name (required)
- `project_id`: GCP project ID (required if not in connection)
- `attributes`: Optional message attributes

## Features

- Google Cloud Pub/Sub integration
- Service account authentication
- Message attributes support
- Connection pooling
- Automatic topic creation (if permissions allow)

