# AWS SQS Module

The AWS SQS Module sends webhook payloads to Amazon Simple Queue Service queues.

## Configuration

```json
{
    "sqs_webhook": {
        "data_type": "json",
        "module": "aws_sqs",
        "connection": "aws_sqs_conn",
        "module-config": {
            "queue_url": "https://sqs.us-east-1.amazonaws.com/123456789/webhook-queue",
            "message_group_id": null,
            "message_deduplication_id": null
        },
        "authorization": "Bearer token"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "aws_sqs_conn": {
        "type": "aws_sqs",
        "aws_access_key_id": "{$AWS_ACCESS_KEY_ID}",
        "aws_secret_access_key": "{$AWS_SECRET_ACCESS_KEY}",
        "region": "us-east-1"
    }
}
```

## Module Configuration Options

- `queue_url`: SQS queue URL (required)
- `message_group_id`: Message group ID for FIFO queues
- `message_deduplication_id`: Deduplication ID for FIFO queues
- `delay_seconds`: Message delay in seconds (default: 0)

## Features

- Standard and FIFO queue support
- Message deduplication
- Delay queues
- AWS credentials via environment variables
- Connection pooling

