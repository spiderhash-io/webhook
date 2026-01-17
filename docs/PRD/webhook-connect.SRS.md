# Webhook Connect - Software Requirements Specification

## Document Information

| Field | Value |
|-------|-------|
| Document Type | Software Requirements Specification (SRS) |
| Feature Name | Webhook Connect |
| Version | 1.0 |
| Status | Draft |
| Created | 2026-01-16 |
| Related PRD | [webhook-connect.PRD.md](./webhook-connect.PRD.md) |

---

## 1. Introduction

### 1.1 Purpose

This document specifies the technical requirements for implementing the Webhook Connect feature. It provides detailed specifications for APIs, protocols, data formats, and system components required to build the Cloud Receiver and Local Connector.

### 1.2 Scope

This SRS covers:
- Cloud Receiver API endpoints and behavior
- Streaming API (WebSocket/SSE) protocol
- Local Connector implementation requirements
- Message formats and data models
- Authentication mechanisms
- Internal queue integration
- Error handling and recovery

### 1.3 References

- PRD: `docs/prd/webhook-connect.PRD.md`
- Architecture: `docs/ARCHITECTURE.md`
- Existing Modules: `src/modules/`

---

## 2. System Architecture

### 2.1 Component Overview

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                              CLOUD RECEIVER                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────┐  │
│  │                            FastAPI Application                                │  │
│  │                                                                               │  │
│  │  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐   │  │
│  │  │   Webhook API       │  │   Streaming API     │  │   Admin API         │   │  │
│  │  │   /webhook/{id}     │  │   /connect/stream   │  │   /admin/channels   │   │  │
│  │  │                     │  │                     │  │                     │   │  │
│  │  │  - POST handler     │  │  - WebSocket        │  │  - Channel mgmt     │   │  │
│  │  │  - Auth validation  │  │  - SSE fallback     │  │  - Token mgmt       │   │  │
│  │  │  - Payload parsing  │  │  - Long-poll        │  │  - Stats            │   │  │
│  │  └──────────┬──────────┘  └──────────┬──────────┘  └─────────────────────┘   │  │
│  │             │                        │                                        │  │
│  │             ▼                        ▼                                        │  │
│  │  ┌──────────────────────────────────────────────────────────────────────┐    │  │
│  │  │                      Channel Manager                                  │    │  │
│  │  │  - Route webhook to channel                                          │    │  │
│  │  │  - Manage channel subscriptions                                      │    │  │
│  │  │  - Track connected clients                                           │    │  │
│  │  └──────────────────────────────────┬───────────────────────────────────┘    │  │
│  │                                     │                                         │  │
│  │                                     ▼                                         │  │
│  │  ┌──────────────────────────────────────────────────────────────────────┐    │  │
│  │  │                      Message Buffer                                   │    │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐                            │    │  │
│  │  │  │   RabbitMQ      │  │   Redis         │   (configurable backend)   │    │  │
│  │  │  │   Adapter       │  │   Adapter       │                            │    │  │
│  │  │  └─────────────────┘  └─────────────────┘                            │    │  │
│  │  └──────────────────────────────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────┐
│                              LOCAL CONNECTOR                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────┐  │
│  │                          Python Application                                   │  │
│  │                                                                               │  │
│  │  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐   │  │
│  │  │   Stream Client     │  │   Message Processor │  │   Module Router     │   │  │
│  │  │                     │  │                     │  │                     │   │  │
│  │  │  - WebSocket conn   │  │  - Deserialize msg  │  │  - Load modules     │   │  │
│  │  │  - Auto-reconnect   │  │  - Validate format  │  │  - Execute chain    │   │  │
│  │  │  - Heartbeat        │  │  - Track processing │  │  - Send ACK         │   │  │
│  │  └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘   │  │
│  │             │                        │                        │               │  │
│  │             ▼                        ▼                        ▼               │  │
│  │  ┌──────────────────────────────────────────────────────────────────────┐    │  │
│  │  │                   Existing Module System                              │    │  │
│  │  │   Kafka │ Redis │ PostgreSQL │ RabbitMQ │ HTTP │ S3 │ ...            │    │  │
│  │  └──────────────────────────────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| **Webhook API** | Receive external webhooks, validate auth, queue to channel |
| **Streaming API** | Manage WebSocket/SSE connections, stream messages to connectors |
| **Channel Manager** | Route messages, manage subscriptions, track clients |
| **Message Buffer** | Persist messages, manage TTL, handle acknowledgments |
| **Stream Client** | Connect to cloud, receive messages, handle reconnection |
| **Message Processor** | Parse messages, coordinate processing, send ACKs |
| **Module Router** | Execute destination modules, handle chains |

---

## 3. API Specifications

### 3.1 Webhook API (Ingest)

#### 3.1.1 Receive Webhook

Receives webhooks from external services and queues them to the appropriate channel.

**Endpoint:** `POST /webhook/{webhook_id}`

**Request:**
```http
POST /webhook/stripe_relay HTTP/1.1
Host: cloud.example.com
Content-Type: application/json
X-Stripe-Signature: t=1234567890,v1=abc123...

{
  "id": "evt_123",
  "type": "payment_intent.succeeded",
  "data": { ... }
}
```

**Response (Success):**
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Webhook-Message-Id: msg_abc123def456

{
  "status": "accepted",
  "message_id": "msg_abc123def456",
  "channel": "stripe-payments"
}
```

**Response (Auth Failure):**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "invalid_signature",
  "message": "HMAC signature validation failed"
}
```

**Response (Queue Full):**
```http
HTTP/1.1 503 Service Unavailable
Content-Type: application/json
Retry-After: 60

{
  "error": "queue_full",
  "message": "Channel buffer at capacity, retry later"
}
```

#### 3.1.2 Message Envelope

When a webhook is received, it's wrapped in an envelope before queuing:

```json
{
  "message_id": "msg_abc123def456",
  "channel": "stripe-payments",
  "webhook_id": "stripe_relay",
  "timestamp": "2026-01-16T10:30:00.123Z",
  "expires_at": "2026-01-17T10:30:00.123Z",
  "metadata": {
    "source_ip": "54.187.174.169",
    "content_type": "application/json",
    "content_length": 1234
  },
  "headers": {
    "X-Stripe-Signature": "t=1234567890,v1=abc123...",
    "User-Agent": "Stripe/1.0"
  },
  "payload": {
    "id": "evt_123",
    "type": "payment_intent.succeeded",
    "data": { ... }
  }
}
```

### 3.2 Streaming API

#### 3.2.1 WebSocket Connection

**Endpoint:** `GET /connect/stream/{channel}`

**Connection Upgrade:**
```http
GET /connect/stream/stripe-payments HTTP/1.1
Host: cloud.example.com
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer ch_tok_abc123...
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
X-Connector-Id: conn_laptop_dev_001
```

**Response (Success):**
```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
X-Channel: stripe-payments
X-Connection-Id: wsc_xyz789
```

**Response (Auth Failure):**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "invalid_channel_token",
  "message": "Token does not match channel 'stripe-payments'"
}
```

#### 3.2.2 WebSocket Message Protocol

All WebSocket messages are JSON-encoded with a `type` field.

**Server → Client Messages:**

| Type | Description |
|------|-------------|
| `webhook` | Webhook message to process |
| `heartbeat` | Keep-alive ping |
| `error` | Error notification |
| `info` | Informational message |

**Client → Server Messages:**

| Type | Description |
|------|-------------|
| `ack` | Acknowledge successful processing |
| `nack` | Negative acknowledge (processing failed) |
| `heartbeat` | Keep-alive pong |

##### Webhook Message (Server → Client)

```json
{
  "type": "webhook",
  "message_id": "msg_abc123def456",
  "sequence": 12345,
  "data": {
    "webhook_id": "stripe_relay",
    "timestamp": "2026-01-16T10:30:00.123Z",
    "headers": {
      "X-Stripe-Signature": "t=1234567890,v1=abc123...",
      "Content-Type": "application/json"
    },
    "payload": {
      "id": "evt_123",
      "type": "payment_intent.succeeded",
      "data": { ... }
    }
  }
}
```

##### Acknowledgment (Client → Server)

**Success ACK:**
```json
{
  "type": "ack",
  "message_id": "msg_abc123def456",
  "processed_at": "2026-01-16T10:30:00.456Z"
}
```

**Negative ACK (with retry):**
```json
{
  "type": "nack",
  "message_id": "msg_abc123def456",
  "error": "destination_unavailable",
  "message": "Kafka connection refused",
  "retry": true
}
```

**Negative ACK (permanent failure):**
```json
{
  "type": "nack",
  "message_id": "msg_abc123def456",
  "error": "invalid_payload",
  "message": "Payload validation failed",
  "retry": false
}
```

##### Heartbeat

**Server → Client:**
```json
{
  "type": "heartbeat",
  "timestamp": "2026-01-16T10:30:00.000Z",
  "server_time": "2026-01-16T10:30:00.000Z"
}
```

**Client → Server:**
```json
{
  "type": "heartbeat",
  "timestamp": "2026-01-16T10:30:00.050Z"
}
```

#### 3.2.3 Server-Sent Events (SSE) Fallback

**Endpoint:** `GET /connect/stream/{channel}/sse`

**Request:**
```http
GET /connect/stream/stripe-payments/sse HTTP/1.1
Host: cloud.example.com
Authorization: Bearer ch_tok_abc123...
Accept: text/event-stream
X-Connector-Id: conn_laptop_dev_001
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Channel: stripe-payments
X-Connection-Id: sse_xyz789

event: connected
data: {"connection_id": "sse_xyz789", "channel": "stripe-payments"}

event: webhook
id: msg_abc123def456
data: {"message_id": "msg_abc123def456", "data": {...}}

event: heartbeat
data: {"timestamp": "2026-01-16T10:30:00.000Z"}
```

**ACK Endpoint for SSE:**

Since SSE is unidirectional, acknowledgments are sent via separate HTTP POST:

```http
POST /connect/ack HTTP/1.1
Host: cloud.example.com
Authorization: Bearer ch_tok_abc123...
Content-Type: application/json
X-Connection-Id: sse_xyz789

{
  "message_id": "msg_abc123def456",
  "status": "ack",
  "processed_at": "2026-01-16T10:30:00.456Z"
}
```

#### 3.2.4 HTTP Long-Polling Fallback

**Endpoint:** `GET /connect/poll/{channel}`

**Request:**
```http
GET /connect/poll/stripe-payments?timeout=30&last_id=msg_abc123 HTTP/1.1
Host: cloud.example.com
Authorization: Bearer ch_tok_abc123...
X-Connector-Id: conn_laptop_dev_001
```

**Response (Messages Available):**
```json
{
  "messages": [
    {
      "message_id": "msg_def456",
      "data": { ... }
    },
    {
      "message_id": "msg_ghi789",
      "data": { ... }
    }
  ],
  "has_more": true,
  "next_poll_after": "msg_ghi789"
}
```

**Response (No Messages, Timeout):**
```json
{
  "messages": [],
  "has_more": false,
  "next_poll_after": null
}
```

### 3.3 Admin API

#### 3.3.1 List Channels

```http
GET /admin/channels HTTP/1.1
Host: cloud.example.com
Authorization: Bearer admin_token_xyz

Response:
{
  "channels": [
    {
      "name": "stripe-payments",
      "webhook_id": "stripe_relay",
      "created_at": "2026-01-01T00:00:00Z",
      "stats": {
        "messages_queued": 150,
        "messages_delivered": 14850,
        "connected_clients": 2
      }
    }
  ]
}
```

#### 3.3.2 Channel Details

```http
GET /admin/channels/stripe-payments HTTP/1.1
Host: cloud.example.com
Authorization: Bearer admin_token_xyz

Response:
{
  "name": "stripe-payments",
  "webhook_id": "stripe_relay",
  "created_at": "2026-01-01T00:00:00Z",
  "config": {
    "ttl_seconds": 86400,
    "max_queue_size": 10000
  },
  "stats": {
    "messages_queued": 150,
    "messages_in_flight": 5,
    "messages_delivered": 14850,
    "messages_expired": 0,
    "messages_dead_lettered": 3
  },
  "connected_clients": [
    {
      "connection_id": "wsc_xyz789",
      "connector_id": "conn_laptop_dev_001",
      "connected_at": "2026-01-16T08:00:00Z",
      "protocol": "websocket",
      "messages_received": 500,
      "last_ack_at": "2026-01-16T10:29:55Z"
    }
  ]
}
```

#### 3.3.3 Rotate Channel Token

```http
POST /admin/channels/stripe-payments/rotate-token HTTP/1.1
Host: cloud.example.com
Authorization: Bearer admin_token_xyz
Content-Type: application/json

{
  "grace_period_seconds": 3600
}

Response:
{
  "channel": "stripe-payments",
  "new_token": "ch_tok_new_abc123...",
  "old_token_expires_at": "2026-01-16T11:30:00Z",
  "message": "Old token valid for 1 hour grace period"
}
```

---

## 4. Data Models

### 4.1 Channel Configuration

```python
from dataclasses import dataclass
from typing import Optional, List
from datetime import timedelta

@dataclass
class ChannelConfig:
    """Configuration for a webhook connect channel."""

    name: str                           # Unique channel identifier
    webhook_id: str                     # Associated webhook endpoint ID
    channel_token: str                  # Authentication token for connectors

    # Queue settings
    ttl: timedelta = timedelta(hours=24)      # Message time-to-live
    max_queue_size: int = 10000               # Maximum messages in queue
    max_message_size: int = 10 * 1024 * 1024  # 10MB max payload

    # Delivery settings
    max_in_flight: int = 100            # Max unacknowledged messages per client
    ack_timeout: timedelta = timedelta(seconds=30)  # Time to wait for ACK

    # Connection settings
    max_connections: int = 10           # Max concurrent connectors
    heartbeat_interval: timedelta = timedelta(seconds=30)

    # Optional settings
    allowed_ips: Optional[List[str]] = None  # IP allowlist
    rate_limit_per_second: Optional[int] = None
```

### 4.2 Message Model

```python
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

@dataclass
class WebhookMessage:
    """A webhook message in the channel queue."""

    message_id: str = field(default_factory=lambda: f"msg_{uuid.uuid4().hex[:16]}")
    channel: str = ""
    webhook_id: str = ""

    # Timing
    received_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    # Original request data
    headers: Dict[str, str] = field(default_factory=dict)
    payload: Any = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Delivery tracking
    sequence: int = 0                    # Monotonic sequence number
    delivery_count: int = 0              # Number of delivery attempts
    last_delivered_at: Optional[datetime] = None
    last_delivered_to: Optional[str] = None  # Connection ID

    # State
    state: str = "pending"  # pending, in_flight, delivered, expired, dead_lettered

    def to_wire_format(self) -> dict:
        """Format for WebSocket transmission."""
        return {
            "type": "webhook",
            "message_id": self.message_id,
            "sequence": self.sequence,
            "data": {
                "webhook_id": self.webhook_id,
                "timestamp": self.received_at.isoformat(),
                "headers": self.headers,
                "payload": self.payload
            }
        }
```

### 4.3 Connection Model

```python
from dataclasses import dataclass, field
from typing import Optional, Set
from datetime import datetime
from enum import Enum

class ConnectionProtocol(Enum):
    WEBSOCKET = "websocket"
    SSE = "sse"
    LONG_POLL = "long_poll"

class ConnectionState(Enum):
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"

@dataclass
class ConnectorConnection:
    """An active connector connection."""

    connection_id: str
    connector_id: str                    # Client-provided identifier
    channel: str
    protocol: ConnectionProtocol

    # Timing
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat_at: Optional[datetime] = None
    last_message_at: Optional[datetime] = None

    # State
    state: ConnectionState = ConnectionState.CONNECTING

    # Message tracking
    in_flight_messages: Set[str] = field(default_factory=set)  # message_ids
    messages_received: int = 0
    messages_acked: int = 0
    messages_nacked: int = 0

    # Client info
    remote_ip: Optional[str] = None
    user_agent: Optional[str] = None
```

### 4.4 Acknowledgment Model

```python
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from enum import Enum

class AckStatus(Enum):
    ACK = "ack"           # Successfully processed
    NACK_RETRY = "nack_retry"    # Failed, should retry
    NACK_REJECT = "nack_reject"  # Failed, don't retry (dead letter)

@dataclass
class MessageAck:
    """Acknowledgment from connector."""

    message_id: str
    status: AckStatus
    processed_at: datetime
    connection_id: str

    # Error info (for NACK)
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    # Processing info
    processing_time_ms: Optional[int] = None
    destination_module: Optional[str] = None
```

---

## 5. Message Buffer Implementation

### 5.1 Buffer Interface

```python
from abc import ABC, abstractmethod
from typing import List, Optional, AsyncIterator
from contextlib import asynccontextmanager

class MessageBufferInterface(ABC):
    """Abstract interface for message buffer backends."""

    @abstractmethod
    async def push(self, channel: str, message: WebhookMessage) -> bool:
        """Add message to channel queue. Returns False if queue full."""
        pass

    @abstractmethod
    async def pop(self, channel: str, count: int = 1) -> List[WebhookMessage]:
        """Get messages from queue (marks as in-flight)."""
        pass

    @abstractmethod
    async def ack(self, channel: str, message_id: str) -> bool:
        """Acknowledge message, remove from queue."""
        pass

    @abstractmethod
    async def nack(self, channel: str, message_id: str, retry: bool) -> bool:
        """Negative acknowledge. If retry=True, return to queue."""
        pass

    @abstractmethod
    async def get_queue_depth(self, channel: str) -> int:
        """Get number of pending messages."""
        pass

    @abstractmethod
    async def get_in_flight_count(self, channel: str) -> int:
        """Get number of messages awaiting acknowledgment."""
        pass

    @abstractmethod
    @asynccontextmanager
    async def subscribe(self, channel: str) -> AsyncIterator[WebhookMessage]:
        """Subscribe to channel, yield messages as they arrive."""
        pass

    @abstractmethod
    async def cleanup_expired(self, channel: str) -> int:
        """Remove expired messages, return count removed."""
        pass
```

### 5.2 RabbitMQ Adapter

```python
import aio_pika
from typing import AsyncIterator
import json

class RabbitMQBuffer(MessageBufferInterface):
    """RabbitMQ-based message buffer."""

    def __init__(self, connection_url: str):
        self.connection_url = connection_url
        self.connection: Optional[aio_pika.Connection] = None
        self.channel: Optional[aio_pika.Channel] = None

    async def connect(self):
        self.connection = await aio_pika.connect_robust(self.connection_url)
        self.channel = await self.connection.channel()
        await self.channel.set_qos(prefetch_count=100)

    def _queue_name(self, channel: str) -> str:
        return f"webhook_connect.{channel}"

    def _dlq_name(self, channel: str) -> str:
        return f"webhook_connect.{channel}.dlq"

    async def push(self, channel: str, message: WebhookMessage) -> bool:
        queue_name = self._queue_name(channel)

        # Ensure queue exists with DLQ
        await self.channel.declare_queue(
            queue_name,
            durable=True,
            arguments={
                "x-dead-letter-exchange": "",
                "x-dead-letter-routing-key": self._dlq_name(channel),
                "x-message-ttl": int(message.expires_at.timestamp() * 1000)
                    if message.expires_at else 86400000  # 24h default
            }
        )

        # Publish message
        await self.channel.default_exchange.publish(
            aio_pika.Message(
                body=json.dumps(message.to_wire_format()).encode(),
                message_id=message.message_id,
                timestamp=message.received_at,
                headers={"channel": channel, "webhook_id": message.webhook_id}
            ),
            routing_key=queue_name
        )
        return True

    async def subscribe(self, channel: str) -> AsyncIterator[WebhookMessage]:
        queue_name = self._queue_name(channel)
        queue = await self.channel.declare_queue(queue_name, durable=True)

        async with queue.iterator() as queue_iter:
            async for amqp_message in queue_iter:
                data = json.loads(amqp_message.body.decode())
                message = WebhookMessage(
                    message_id=amqp_message.message_id,
                    channel=channel,
                    payload=data.get("data", {}).get("payload"),
                    headers=data.get("data", {}).get("headers", {})
                )
                message._amqp_message = amqp_message  # For ack/nack
                yield message

    async def ack(self, channel: str, message_id: str) -> bool:
        # Implementation uses stored _amqp_message reference
        # In practice, track in-flight messages in a dict
        pass

    async def nack(self, channel: str, message_id: str, retry: bool) -> bool:
        # If retry=False, message goes to DLQ via reject
        pass
```

### 5.3 Redis Adapter

```python
import redis.asyncio as redis
import json
from datetime import datetime

class RedisBuffer(MessageBufferInterface):
    """Redis-based message buffer using Streams."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis: Optional[redis.Redis] = None

    async def connect(self):
        self.redis = await redis.from_url(self.redis_url)

    def _stream_key(self, channel: str) -> str:
        return f"webhook_connect:stream:{channel}"

    def _pending_key(self, channel: str) -> str:
        return f"webhook_connect:pending:{channel}"

    def _consumer_group(self, channel: str) -> str:
        return f"webhook_connect_consumers:{channel}"

    async def push(self, channel: str, message: WebhookMessage) -> bool:
        stream_key = self._stream_key(channel)

        # Add to stream
        await self.redis.xadd(
            stream_key,
            {
                "message_id": message.message_id,
                "data": json.dumps(message.to_wire_format()),
                "expires_at": message.expires_at.isoformat() if message.expires_at else ""
            },
            maxlen=10000  # Max queue size
        )
        return True

    async def subscribe(self, channel: str) -> AsyncIterator[WebhookMessage]:
        stream_key = self._stream_key(channel)
        group = self._consumer_group(channel)
        consumer = f"consumer_{datetime.utcnow().timestamp()}"

        # Create consumer group if not exists
        try:
            await self.redis.xgroup_create(stream_key, group, id="0", mkstream=True)
        except redis.ResponseError:
            pass  # Group already exists

        while True:
            # Read from stream
            messages = await self.redis.xreadgroup(
                group, consumer,
                {stream_key: ">"},
                count=10,
                block=5000  # 5 second block
            )

            for stream, entries in messages:
                for entry_id, data in entries:
                    msg_data = json.loads(data[b"data"].decode())
                    message = WebhookMessage(
                        message_id=data[b"message_id"].decode(),
                        channel=channel,
                        payload=msg_data.get("data", {}).get("payload"),
                        headers=msg_data.get("data", {}).get("headers", {})
                    )
                    message._redis_id = entry_id  # For ack
                    yield message

    async def ack(self, channel: str, message_id: str) -> bool:
        # XACK to acknowledge
        pass
```

---

## 6. Cloud Receiver Implementation

### 6.1 WebhookConnectModule

New module that queues webhooks to channels instead of processing directly:

```python
# src/modules/webhook_connect.py

from typing import Any, Dict
from src.modules.base import BaseModule
from src.webhook_connect.channel_manager import ChannelManager
from src.webhook_connect.models import WebhookMessage
from datetime import datetime, timedelta

class WebhookConnectModule(BaseModule):
    """Module that queues webhooks to a channel for remote consumption."""

    def __init__(self, config: Dict[str, Any], connection_config: Dict[str, Any]):
        super().__init__(config, connection_config)
        self.channel_name = config.get("channel")
        self.channel_token = config.get("channel_token")
        self.ttl_seconds = config.get("ttl_seconds", 86400)  # 24h default
        self.channel_manager: ChannelManager = None  # Injected

    async def setup(self) -> None:
        """Register channel with channel manager."""
        await self.channel_manager.register_channel(
            name=self.channel_name,
            token=self.channel_token,
            ttl=timedelta(seconds=self.ttl_seconds)
        )

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Queue webhook to channel."""
        message = WebhookMessage(
            channel=self.channel_name,
            webhook_id=self.webhook_id,
            payload=payload,
            headers=headers,
            received_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=self.ttl_seconds)
        )

        success = await self.channel_manager.publish(self.channel_name, message)

        if not success:
            raise Exception(f"Failed to queue message to channel {self.channel_name}")

    async def teardown(self) -> None:
        """Cleanup."""
        pass
```

### 6.2 Channel Manager

```python
# src/webhook_connect/channel_manager.py

from typing import Dict, Optional, Set
import asyncio
from dataclasses import dataclass, field
from datetime import timedelta

from .models import WebhookMessage, ChannelConfig, ConnectorConnection
from .buffer import MessageBufferInterface

class ChannelManager:
    """Manages channels, connections, and message routing."""

    def __init__(self, buffer: MessageBufferInterface):
        self.buffer = buffer
        self.channels: Dict[str, ChannelConfig] = {}
        self.connections: Dict[str, ConnectorConnection] = {}  # connection_id -> connection
        self.channel_connections: Dict[str, Set[str]] = {}  # channel -> set of connection_ids
        self._lock = asyncio.Lock()

    async def register_channel(
        self,
        name: str,
        token: str,
        ttl: timedelta = timedelta(hours=24),
        **kwargs
    ) -> ChannelConfig:
        """Register a new channel or update existing."""
        async with self._lock:
            config = ChannelConfig(
                name=name,
                webhook_id=kwargs.get("webhook_id", ""),
                channel_token=token,
                ttl=ttl,
                **kwargs
            )
            self.channels[name] = config
            if name not in self.channel_connections:
                self.channel_connections[name] = set()
            return config

    def validate_token(self, channel: str, token: str) -> bool:
        """Validate channel access token."""
        if channel not in self.channels:
            return False
        # Support grace period for token rotation
        config = self.channels[channel]
        return token == config.channel_token

    async def publish(self, channel: str, message: WebhookMessage) -> bool:
        """Publish message to channel."""
        if channel not in self.channels:
            return False

        config = self.channels[channel]

        # Check queue size limit
        depth = await self.buffer.get_queue_depth(channel)
        if depth >= config.max_queue_size:
            return False

        # Push to buffer
        return await self.buffer.push(channel, message)

    async def add_connection(self, connection: ConnectorConnection) -> bool:
        """Add a new connector connection."""
        async with self._lock:
            channel = connection.channel
            if channel not in self.channels:
                return False

            config = self.channels[channel]
            current_count = len(self.channel_connections.get(channel, set()))

            if current_count >= config.max_connections:
                return False

            self.connections[connection.connection_id] = connection
            self.channel_connections[channel].add(connection.connection_id)
            return True

    async def remove_connection(self, connection_id: str) -> None:
        """Remove a connector connection."""
        async with self._lock:
            if connection_id in self.connections:
                conn = self.connections.pop(connection_id)
                self.channel_connections[conn.channel].discard(connection_id)

                # Return in-flight messages to queue
                for msg_id in conn.in_flight_messages:
                    await self.buffer.nack(conn.channel, msg_id, retry=True)

    async def get_channel_stats(self, channel: str) -> Dict:
        """Get channel statistics."""
        if channel not in self.channels:
            return {}

        return {
            "queue_depth": await self.buffer.get_queue_depth(channel),
            "in_flight": await self.buffer.get_in_flight_count(channel),
            "connected_clients": len(self.channel_connections.get(channel, set()))
        }
```

### 6.3 Streaming API Endpoints

```python
# src/webhook_connect/api.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends, Header
from fastapi.responses import StreamingResponse
from typing import Optional
import asyncio
import json

from .channel_manager import ChannelManager
from .models import ConnectorConnection, ConnectionProtocol, ConnectionState

router = APIRouter(prefix="/connect")

# Dependency to get channel manager
async def get_channel_manager() -> ChannelManager:
    from src.main import app
    return app.state.channel_manager


@router.websocket("/stream/{channel}")
async def websocket_stream(
    websocket: WebSocket,
    channel: str,
    channel_manager: ChannelManager = Depends(get_channel_manager)
):
    """WebSocket endpoint for streaming webhooks to connector."""

    # Extract auth token from headers or query
    token = websocket.headers.get("authorization", "").replace("Bearer ", "")
    if not token:
        token = websocket.query_params.get("token", "")

    # Validate token
    if not channel_manager.validate_token(channel, token):
        await websocket.close(code=4001, reason="Invalid channel token")
        return

    # Accept connection
    await websocket.accept()

    # Create connection record
    connector_id = websocket.headers.get("x-connector-id", "unknown")
    connection = ConnectorConnection(
        connection_id=f"wsc_{id(websocket)}",
        connector_id=connector_id,
        channel=channel,
        protocol=ConnectionProtocol.WEBSOCKET,
        remote_ip=websocket.client.host if websocket.client else None,
        user_agent=websocket.headers.get("user-agent")
    )

    # Register connection
    if not await channel_manager.add_connection(connection):
        await websocket.close(code=4003, reason="Max connections reached")
        return

    connection.state = ConnectionState.CONNECTED

    try:
        # Start message streaming and heartbeat tasks
        await asyncio.gather(
            _stream_messages(websocket, channel, connection, channel_manager),
            _handle_client_messages(websocket, channel, connection, channel_manager),
            _send_heartbeats(websocket, connection)
        )
    except WebSocketDisconnect:
        pass
    finally:
        connection.state = ConnectionState.DISCONNECTED
        await channel_manager.remove_connection(connection.connection_id)


async def _stream_messages(
    websocket: WebSocket,
    channel: str,
    connection: ConnectorConnection,
    channel_manager: ChannelManager
):
    """Stream messages from buffer to websocket."""
    config = channel_manager.channels[channel]
    buffer = channel_manager.buffer

    async for message in buffer.subscribe(channel):
        # Check in-flight limit
        while len(connection.in_flight_messages) >= config.max_in_flight:
            await asyncio.sleep(0.1)  # Backpressure

        # Track in-flight
        connection.in_flight_messages.add(message.message_id)
        message.delivery_count += 1
        message.last_delivered_to = connection.connection_id

        # Send to client
        await websocket.send_json(message.to_wire_format())
        connection.messages_received += 1


async def _handle_client_messages(
    websocket: WebSocket,
    channel: str,
    connection: ConnectorConnection,
    channel_manager: ChannelManager
):
    """Handle ACK/NACK messages from client."""
    buffer = channel_manager.buffer

    while True:
        data = await websocket.receive_json()
        msg_type = data.get("type")

        if msg_type == "ack":
            message_id = data.get("message_id")
            if message_id in connection.in_flight_messages:
                await buffer.ack(channel, message_id)
                connection.in_flight_messages.discard(message_id)
                connection.messages_acked += 1

        elif msg_type == "nack":
            message_id = data.get("message_id")
            retry = data.get("retry", True)
            if message_id in connection.in_flight_messages:
                await buffer.nack(channel, message_id, retry=retry)
                connection.in_flight_messages.discard(message_id)
                connection.messages_nacked += 1

        elif msg_type == "heartbeat":
            connection.last_heartbeat_at = datetime.utcnow()


async def _send_heartbeats(websocket: WebSocket, connection: ConnectorConnection):
    """Send periodic heartbeats."""
    while connection.state == ConnectionState.CONNECTED:
        await asyncio.sleep(30)
        await websocket.send_json({
            "type": "heartbeat",
            "timestamp": datetime.utcnow().isoformat()
        })


@router.get("/stream/{channel}/sse")
async def sse_stream(
    channel: str,
    authorization: str = Header(...),
    x_connector_id: str = Header("unknown"),
    channel_manager: ChannelManager = Depends(get_channel_manager)
):
    """Server-Sent Events endpoint for streaming webhooks."""

    token = authorization.replace("Bearer ", "")
    if not channel_manager.validate_token(channel, token):
        raise HTTPException(status_code=401, detail="Invalid channel token")

    async def event_generator():
        # Create connection
        connection = ConnectorConnection(
            connection_id=f"sse_{id(event_generator)}",
            connector_id=x_connector_id,
            channel=channel,
            protocol=ConnectionProtocol.SSE
        )

        if not await channel_manager.add_connection(connection):
            yield f"event: error\ndata: {{\"error\": \"max_connections\"}}\n\n"
            return

        try:
            yield f"event: connected\ndata: {{\"connection_id\": \"{connection.connection_id}\"}}\n\n"

            async for message in channel_manager.buffer.subscribe(channel):
                connection.in_flight_messages.add(message.message_id)
                data = json.dumps(message.to_wire_format())
                yield f"event: webhook\nid: {message.message_id}\ndata: {data}\n\n"
        finally:
            await channel_manager.remove_connection(connection.connection_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Channel": channel
        }
    )


@router.post("/ack")
async def acknowledge_message(
    message_id: str,
    status: str,  # "ack" or "nack"
    x_connection_id: str = Header(...),
    retry: bool = True,
    channel_manager: ChannelManager = Depends(get_channel_manager)
):
    """ACK endpoint for SSE connections."""

    if x_connection_id not in channel_manager.connections:
        raise HTTPException(status_code=404, detail="Connection not found")

    connection = channel_manager.connections[x_connection_id]
    buffer = channel_manager.buffer

    if message_id not in connection.in_flight_messages:
        raise HTTPException(status_code=404, detail="Message not in flight")

    if status == "ack":
        await buffer.ack(connection.channel, message_id)
        connection.messages_acked += 1
    else:
        await buffer.nack(connection.channel, message_id, retry=retry)
        connection.messages_nacked += 1

    connection.in_flight_messages.discard(message_id)

    return {"status": "ok"}
```

---

## 7. Local Connector Implementation

### 7.1 Connector Main

```python
# src/connector/main.py

import asyncio
import signal
from typing import Dict, Any
import json

from .stream_client import StreamClient
from .message_processor import MessageProcessor
from .config import ConnectorConfig

class WebhookConnector:
    """Local webhook connector that receives webhooks from cloud and routes locally."""

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.clients: Dict[str, StreamClient] = {}
        self.processor = MessageProcessor(config)
        self._shutdown = asyncio.Event()

    async def start(self):
        """Start the connector."""
        print(f"Starting Webhook Connector...")
        print(f"Cloud URL: {self.config.cloud_url}")
        print(f"Channels: {list(self.config.routes.keys())}")

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_shutdown)

        # Start processor
        await self.processor.start()

        # Connect to each channel
        tasks = []
        for channel, route_config in self.config.routes.items():
            client = StreamClient(
                cloud_url=self.config.cloud_url,
                channel=channel,
                token=route_config.token,
                processor=self.processor,
                connector_id=self.config.connector_id
            )
            self.clients[channel] = client
            tasks.append(asyncio.create_task(client.run()))

        # Wait for shutdown or client errors
        await asyncio.gather(*tasks, return_exceptions=True)

    def _handle_shutdown(self):
        """Handle shutdown signal."""
        print("\nShutting down...")
        self._shutdown.set()
        for client in self.clients.values():
            client.stop()

    async def stop(self):
        """Stop the connector gracefully."""
        self._shutdown.set()

        # Wait for in-flight messages to complete
        await self.processor.drain()

        # Close all connections
        for client in self.clients.values():
            await client.close()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Webhook Connect Local Connector")
    parser.add_argument("--config", required=True, help="Path to connector config file")
    args = parser.parse_args()

    with open(args.config) as f:
        config_data = json.load(f)

    config = ConnectorConfig.from_dict(config_data)
    connector = WebhookConnector(config)

    asyncio.run(connector.start())


if __name__ == "__main__":
    main()
```

### 7.2 Stream Client

```python
# src/connector/stream_client.py

import asyncio
import websockets
from websockets.exceptions import ConnectionClosed
from typing import Optional
from datetime import datetime
import json

from .message_processor import MessageProcessor

class StreamClient:
    """WebSocket client that connects to cloud and receives messages."""

    def __init__(
        self,
        cloud_url: str,
        channel: str,
        token: str,
        processor: MessageProcessor,
        connector_id: str = "default"
    ):
        self.cloud_url = cloud_url
        self.channel = channel
        self.token = token
        self.processor = processor
        self.connector_id = connector_id

        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self._running = True
        self._reconnect_delay = 1  # Initial reconnect delay in seconds
        self._max_reconnect_delay = 60

    async def run(self):
        """Main loop - connect, receive, reconnect on failure."""
        while self._running:
            try:
                await self._connect_and_receive()
            except ConnectionClosed as e:
                print(f"[{self.channel}] Connection closed: {e}")
            except Exception as e:
                print(f"[{self.channel}] Error: {e}")

            if self._running:
                print(f"[{self.channel}] Reconnecting in {self._reconnect_delay}s...")
                await asyncio.sleep(self._reconnect_delay)
                self._reconnect_delay = min(
                    self._reconnect_delay * 2,
                    self._max_reconnect_delay
                )

    async def _connect_and_receive(self):
        """Connect to cloud and process messages."""
        url = f"{self.cloud_url}/{self.channel}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Connector-Id": self.connector_id
        }

        print(f"[{self.channel}] Connecting to {url}...")

        async with websockets.connect(url, extra_headers=headers) as ws:
            self.websocket = ws
            self._reconnect_delay = 1  # Reset on successful connection
            print(f"[{self.channel}] Connected!")

            # Start heartbeat responder
            asyncio.create_task(self._heartbeat_responder())

            # Process messages
            async for raw_message in ws:
                message = json.loads(raw_message)
                await self._handle_message(message)

    async def _handle_message(self, message: dict):
        """Handle incoming message from cloud."""
        msg_type = message.get("type")

        if msg_type == "webhook":
            message_id = message.get("message_id")
            data = message.get("data", {})

            print(f"[{self.channel}] Received: {message_id}")

            # Process through destination modules
            try:
                await self.processor.process(
                    channel=self.channel,
                    message_id=message_id,
                    payload=data.get("payload"),
                    headers=data.get("headers", {})
                )

                # Send ACK
                await self._send_ack(message_id)
                print(f"[{self.channel}] ACK: {message_id}")

            except Exception as e:
                print(f"[{self.channel}] Processing failed: {e}")
                await self._send_nack(message_id, str(e), retry=True)

        elif msg_type == "heartbeat":
            # Respond to heartbeat
            await self.websocket.send(json.dumps({
                "type": "heartbeat",
                "timestamp": datetime.utcnow().isoformat()
            }))

        elif msg_type == "error":
            print(f"[{self.channel}] Server error: {message}")

    async def _send_ack(self, message_id: str):
        """Send acknowledgment to cloud."""
        await self.websocket.send(json.dumps({
            "type": "ack",
            "message_id": message_id,
            "processed_at": datetime.utcnow().isoformat()
        }))

    async def _send_nack(self, message_id: str, error: str, retry: bool):
        """Send negative acknowledgment to cloud."""
        await self.websocket.send(json.dumps({
            "type": "nack",
            "message_id": message_id,
            "error": error,
            "retry": retry
        }))

    async def _heartbeat_responder(self):
        """Respond to heartbeats."""
        # Handled in _handle_message
        pass

    def stop(self):
        """Signal to stop the client."""
        self._running = False

    async def close(self):
        """Close the connection."""
        self._running = False
        if self.websocket:
            await self.websocket.close()
```

### 7.3 Message Processor

```python
# src/connector/message_processor.py

import asyncio
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

from src.modules.registry import ModuleRegistry
from src.chain_processor import ChainProcessor
from .config import ConnectorConfig, RouteConfig

class MessageProcessor:
    """Processes webhook messages and routes to destination modules."""

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.routes = config.routes
        self.registry = ModuleRegistry()
        self._in_flight: Dict[str, asyncio.Task] = {}
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._executor = ThreadPoolExecutor(max_workers=config.concurrency)

    async def start(self):
        """Initialize modules."""
        for channel, route_config in self.routes.items():
            # Pre-initialize modules for each route
            await self._init_route_modules(channel, route_config)

    async def _init_route_modules(self, channel: str, route_config: RouteConfig):
        """Initialize modules for a route."""
        if route_config.chain:
            # Chain mode - multiple modules
            for chain_item in route_config.chain:
                module_class = self.registry.get(chain_item.module)
                # Module will be instantiated per-message
        else:
            # Single module mode
            module_class = self.registry.get(route_config.module)

    async def process(
        self,
        channel: str,
        message_id: str,
        payload: Any,
        headers: Dict[str, str]
    ):
        """Process a webhook message through destination modules."""

        if channel not in self.routes:
            raise ValueError(f"No route configured for channel: {channel}")

        route_config = self.routes[channel]

        async with self._semaphore:
            if route_config.chain:
                # Chain processing
                processor = ChainProcessor(
                    chain_config=route_config.chain,
                    chain_execution=route_config.chain_config.get("execution", "sequential")
                )
                await processor.process(payload, headers)
            else:
                # Single module processing
                module_class = self.registry.get(route_config.module)
                module = module_class(
                    config=route_config.module_config,
                    connection_config=self._get_connection_config(route_config.connection)
                )

                try:
                    await module.setup()
                    await module.process(payload, headers)
                finally:
                    await module.teardown()

    def _get_connection_config(self, connection_name: str) -> Dict[str, Any]:
        """Get connection configuration by name."""
        return self.config.connections.get(connection_name, {})

    async def drain(self):
        """Wait for all in-flight messages to complete."""
        if self._in_flight:
            await asyncio.gather(*self._in_flight.values(), return_exceptions=True)
```

### 7.4 Connector Configuration

```python
# src/connector/config.py

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
import os
import re

@dataclass
class ChainItemConfig:
    module: str
    connection: Optional[str] = None
    module_config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RouteConfig:
    token: str
    module: Optional[str] = None
    connection: Optional[str] = None
    module_config: Dict[str, Any] = field(default_factory=dict)
    chain: Optional[List[ChainItemConfig]] = None
    chain_config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ConnectorConfig:
    cloud_url: str
    connector_id: str
    routes: Dict[str, RouteConfig]
    connections: Dict[str, Dict[str, Any]]
    concurrency: int = 10

    @classmethod
    def from_dict(cls, data: dict) -> "ConnectorConfig":
        """Create config from dictionary, resolving env vars."""

        def resolve_env_vars(value: Any) -> Any:
            if isinstance(value, str):
                # Replace {$VAR_NAME} with environment variable
                pattern = r'\{\$([A-Z_][A-Z0-9_]*)\}'
                matches = re.findall(pattern, value)
                for match in matches:
                    env_value = os.environ.get(match, "")
                    value = value.replace(f"{{${match}}}", env_value)
                return value
            elif isinstance(value, dict):
                return {k: resolve_env_vars(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [resolve_env_vars(v) for v in value]
            return value

        data = resolve_env_vars(data)

        # Parse routes
        routes = {}
        for channel, route_data in data.get("routes", {}).items():
            chain = None
            if "chain" in route_data:
                chain = [
                    ChainItemConfig(
                        module=item.get("module"),
                        connection=item.get("connection"),
                        module_config=item.get("module-config", {})
                    )
                    for item in route_data["chain"]
                ]

            routes[channel] = RouteConfig(
                token=route_data.get("token", ""),
                module=route_data.get("module"),
                connection=route_data.get("connection"),
                module_config=route_data.get("module-config", {}),
                chain=chain,
                chain_config=route_data.get("chain-config", {})
            )

        return cls(
            cloud_url=data.get("cloud", {}).get("url", ""),
            connector_id=data.get("cloud", {}).get("connector_id", "default"),
            routes=routes,
            connections=data.get("connections", {}),
            concurrency=data.get("concurrency", 10)
        )
```

---

## 8. Configuration Schema

### 8.1 Cloud Receiver Configuration

**webhooks.json** with webhook_connect module:

```json
{
  "$schema": "./schemas/webhooks.schema.json",

  "stripe_relay": {
    "data_type": "json",
    "module": "webhook_connect",
    "module-config": {
      "channel": "stripe-payments",
      "channel_token": "{$STRIPE_CHANNEL_TOKEN}",
      "ttl_seconds": 86400,
      "max_queue_size": 10000,
      "max_connections": 10
    },
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    },
    "rate_limit": {
      "max_requests": 100,
      "window_seconds": 60
    }
  },

  "github_relay": {
    "data_type": "json",
    "module": "webhook_connect",
    "module-config": {
      "channel": "github-events",
      "channel_token": "{$GITHUB_CHANNEL_TOKEN}"
    },
    "hmac": {
      "secret": "{$GITHUB_WEBHOOK_SECRET}",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    }
  }
}
```

### 8.2 Local Connector Configuration

**connector.json**:

```json
{
  "$schema": "./schemas/connector.schema.json",

  "cloud": {
    "url": "wss://webhook-cloud.example.com/connect/stream",
    "connector_id": "prod-server-01"
  },

  "concurrency": 10,

  "routes": {
    "stripe-payments": {
      "token": "{$STRIPE_CHANNEL_TOKEN}",
      "module": "kafka",
      "connection": "local_kafka",
      "module-config": {
        "topic": "payment-events"
      }
    },

    "github-events": {
      "token": "{$GITHUB_CHANNEL_TOKEN}",
      "chain": [
        {
          "module": "postgresql",
          "connection": "local_db",
          "module-config": {
            "table": "github_events",
            "storage_mode": "json"
          }
        },
        {
          "module": "redis_rq",
          "connection": "local_redis",
          "module-config": {
            "queue_name": "ci-triggers"
          }
        }
      ],
      "chain-config": {
        "execution": "parallel",
        "continue_on_error": true
      }
    }
  },

  "connections": {
    "local_kafka": {
      "type": "kafka",
      "bootstrap_servers": "localhost:9092"
    },
    "local_db": {
      "type": "postgresql",
      "host": "localhost",
      "port": 5432,
      "database": "webhooks",
      "user": "{$DB_USER}",
      "password": "{$DB_PASSWORD}"
    },
    "local_redis": {
      "type": "redis",
      "host": "localhost",
      "port": 6379
    }
  }
}
```

### 8.3 JSON Schema for Connector Config

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "connector.schema.json",
  "title": "Webhook Connector Configuration",
  "type": "object",
  "required": ["cloud", "routes"],
  "properties": {
    "cloud": {
      "type": "object",
      "required": ["url"],
      "properties": {
        "url": {
          "type": "string",
          "format": "uri",
          "description": "WebSocket URL to cloud receiver"
        },
        "connector_id": {
          "type": "string",
          "description": "Unique identifier for this connector"
        }
      }
    },
    "concurrency": {
      "type": "integer",
      "minimum": 1,
      "maximum": 100,
      "default": 10,
      "description": "Maximum concurrent message processing"
    },
    "routes": {
      "type": "object",
      "additionalProperties": {
        "$ref": "#/$defs/route"
      }
    },
    "connections": {
      "type": "object",
      "additionalProperties": {
        "type": "object"
      }
    }
  },
  "$defs": {
    "route": {
      "type": "object",
      "required": ["token"],
      "properties": {
        "token": {
          "type": "string",
          "description": "Channel authentication token"
        },
        "module": {
          "type": "string",
          "description": "Destination module name"
        },
        "connection": {
          "type": "string",
          "description": "Connection name for the module"
        },
        "module-config": {
          "type": "object",
          "description": "Module-specific configuration"
        },
        "chain": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/chainItem"
          }
        },
        "chain-config": {
          "type": "object",
          "properties": {
            "execution": {
              "enum": ["sequential", "parallel"]
            },
            "continue_on_error": {
              "type": "boolean"
            }
          }
        }
      }
    },
    "chainItem": {
      "type": "object",
      "required": ["module"],
      "properties": {
        "module": {"type": "string"},
        "connection": {"type": "string"},
        "module-config": {"type": "object"}
      }
    }
  }
}
```

---

## 9. Error Handling

### 9.1 Error Codes

| Code | Name | Description | Action |
|------|------|-------------|--------|
| 4001 | `invalid_token` | Channel token invalid/expired | Connector should update token |
| 4002 | `channel_not_found` | Channel does not exist | Check configuration |
| 4003 | `max_connections` | Too many connectors | Wait or use different channel |
| 4004 | `rate_limited` | Too many requests | Slow down |
| 4005 | `message_too_large` | Payload exceeds limit | Cannot process |
| 5001 | `buffer_full` | Queue at capacity | Retry later |
| 5002 | `buffer_error` | Queue backend error | Retry later |
| 5003 | `internal_error` | Unexpected server error | Retry later |

### 9.2 Retry Strategy

```python
# Connector retry configuration
RETRY_CONFIG = {
    "initial_delay": 1.0,      # First retry after 1 second
    "max_delay": 60.0,         # Cap at 60 seconds
    "multiplier": 2.0,         # Double delay each retry
    "max_attempts": 10,        # Give up after 10 attempts
    "jitter": 0.1              # Add 10% random jitter
}

async def retry_with_backoff(func, *args, **kwargs):
    delay = RETRY_CONFIG["initial_delay"]

    for attempt in range(RETRY_CONFIG["max_attempts"]):
        try:
            return await func(*args, **kwargs)
        except RetryableError as e:
            if attempt == RETRY_CONFIG["max_attempts"] - 1:
                raise

            jitter = delay * RETRY_CONFIG["jitter"] * random.random()
            await asyncio.sleep(delay + jitter)

            delay = min(
                delay * RETRY_CONFIG["multiplier"],
                RETRY_CONFIG["max_delay"]
            )
```

### 9.3 Dead Letter Handling

Messages that fail permanently (NACK with `retry=false`) go to dead letter queue:

```python
async def handle_dead_letter(channel: str, message: WebhookMessage, error: str):
    """Move message to dead letter storage."""

    dead_letter = {
        "original_message": message.to_wire_format(),
        "channel": channel,
        "error": error,
        "failed_at": datetime.utcnow().isoformat(),
        "delivery_attempts": message.delivery_count
    }

    # Store in DLQ (RabbitMQ DLX or Redis sorted set)
    await buffer.push_dead_letter(channel, dead_letter)

    # Optionally notify admin
    if config.dead_letter_webhook:
        await notify_dead_letter(config.dead_letter_webhook, dead_letter)
```

---

## 10. Performance Requirements

### 10.1 Throughput

| Metric | Requirement |
|--------|-------------|
| Messages ingested per second (per channel) | 1,000 |
| Messages delivered per second (per connector) | 500 |
| Concurrent connections per channel | 10 |
| Total channels per cloud instance | 100 |

### 10.2 Latency

| Metric | Target |
|--------|--------|
| Webhook ingest (receive to queued) | < 50ms p95 |
| End-to-end (receive to connector ACK) | < 500ms p95 |
| WebSocket message delivery | < 10ms p95 |
| Reconnection time | < 5 seconds |

### 10.3 Resource Limits

| Resource | Limit |
|----------|-------|
| Max message size | 10 MB |
| Max queue depth per channel | 10,000 messages |
| Max in-flight per connection | 100 messages |
| Message TTL default | 24 hours |
| Connection idle timeout | 5 minutes |

---

## 11. Testing Requirements

### 11.1 Unit Tests

| Component | Test Coverage |
|-----------|---------------|
| WebhookConnectModule | Queue publishing, error handling |
| ChannelManager | Registration, token validation, connection tracking |
| MessageBuffer (RabbitMQ) | Push, pop, ack, nack, TTL |
| MessageBuffer (Redis) | Push, pop, ack, nack, TTL |
| StreamClient | Connect, reconnect, message handling, ACK/NACK |
| MessageProcessor | Module execution, chain processing |

### 11.2 Integration Tests

| Test Scenario | Description |
|---------------|-------------|
| End-to-end flow | Webhook → Cloud → Connector → Destination |
| Connector offline | Messages queue, deliver on reconnect |
| Connector crash | In-flight messages redelivered |
| Token rotation | Grace period, old token expires |
| Queue full | 503 returned, no data loss |
| Message expiry | TTL enforcement, dead letter |
| Multiple connectors | Load distribution, no duplicates |

### 11.3 Performance Tests

| Test | Target |
|------|--------|
| Sustained throughput | 1,000 msg/sec for 10 minutes |
| Burst handling | 10,000 messages in 10 seconds |
| Connection storm | 100 connectors connecting simultaneously |
| Large messages | 10 MB payload processing |
| Long-running | 24 hour stability test |

---

## 12. Deployment

### 12.1 Cloud Receiver Deployment

```yaml
# docker-compose.cloud.yaml
version: "3.8"

services:
  webhook-cloud:
    image: core-webhook-module:latest
    ports:
      - "8000:8000"
    environment:
      - WEBHOOK_CONNECT_ENABLED=true
      - WEBHOOK_CONNECT_BUFFER=rabbitmq
      - RABBITMQ_URL=amqp://rabbitmq:5672
    depends_on:
      - rabbitmq
    deploy:
      replicas: 3

  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "5672:5672"
      - "15672:15672"
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq

volumes:
  rabbitmq_data:
```

### 12.2 Local Connector Deployment

```bash
# Install connector
pip install webhook-connector

# Run with config file
webhook-connect --config connector.json

# Or run with Docker
docker run -v $(pwd)/connector.json:/app/connector.json \
  webhook-connector:latest --config /app/connector.json
```

### 12.3 Environment Variables

**Cloud Receiver:**

| Variable | Description | Default |
|----------|-------------|---------|
| `WEBHOOK_CONNECT_ENABLED` | Enable webhook connect feature | `false` |
| `WEBHOOK_CONNECT_BUFFER` | Buffer backend (`rabbitmq` or `redis`) | `rabbitmq` |
| `RABBITMQ_URL` | RabbitMQ connection URL | - |
| `REDIS_URL` | Redis connection URL | - |
| `WEBHOOK_CONNECT_DEFAULT_TTL` | Default message TTL in seconds | `86400` |

**Local Connector:**

| Variable | Description | Default |
|----------|-------------|---------|
| `CLOUD_URL` | Cloud receiver WebSocket URL | - |
| `CONNECTOR_ID` | Unique connector identifier | `default` |
| `CONCURRENCY` | Max concurrent message processing | `10` |
| `LOG_LEVEL` | Logging level | `INFO` |

---

## 13. Security Considerations

### 13.1 Transport Security

- All connections MUST use TLS 1.2+
- WebSocket connections use `wss://` protocol
- Certificate validation enabled by default
- Option to use custom CA certificates

### 13.2 Authentication Security

- Channel tokens should be at least 32 characters
- Tokens should be generated using cryptographically secure random
- Token rotation supported with grace period
- Failed auth attempts logged with rate limiting

### 13.3 Data Security

- Payload data not logged by default
- Credential cleanup applied to headers
- Option for message encryption at rest
- No sensitive data in error messages

---

## 14. Monitoring and Observability

### 14.1 Metrics (Prometheus format)

```
# Cloud Receiver Metrics
webhook_connect_messages_received_total{channel="stripe-payments"} 15000
webhook_connect_messages_queued{channel="stripe-payments"} 150
webhook_connect_messages_delivered_total{channel="stripe-payments"} 14850
webhook_connect_messages_expired_total{channel="stripe-payments"} 0
webhook_connect_messages_dead_lettered_total{channel="stripe-payments"} 3
webhook_connect_connections_active{channel="stripe-payments"} 2
webhook_connect_ingest_latency_seconds{channel="stripe-payments",quantile="0.95"} 0.025

# Connector Metrics
webhook_connector_messages_received_total{channel="stripe-payments"} 500
webhook_connector_messages_acked_total{channel="stripe-payments"} 498
webhook_connector_messages_nacked_total{channel="stripe-payments"} 2
webhook_connector_processing_latency_seconds{channel="stripe-payments",quantile="0.95"} 0.150
webhook_connector_connection_status{channel="stripe-payments"} 1
```

### 14.2 Health Endpoints

**Cloud Receiver:**
```
GET /health
{
  "status": "healthy",
  "buffer": "connected",
  "channels": 5,
  "connections": 12
}
```

**Local Connector:**
```
GET /health
{
  "status": "healthy",
  "channels": {
    "stripe-payments": "connected",
    "github-events": "reconnecting"
  },
  "in_flight": 5
}
```

### 14.3 Logging

Structured JSON logging with correlation IDs:

```json
{
  "timestamp": "2026-01-16T10:30:00.123Z",
  "level": "INFO",
  "component": "cloud_receiver",
  "channel": "stripe-payments",
  "message_id": "msg_abc123",
  "action": "message_queued",
  "latency_ms": 12
}
```

---

## 15. Appendix

### 15.1 File Structure

```
src/
├── webhook_connect/
│   ├── __init__.py
│   ├── models.py              # Data models
│   ├── channel_manager.py     # Channel management
│   ├── buffer/
│   │   ├── __init__.py
│   │   ├── interface.py       # Buffer interface
│   │   ├── rabbitmq.py        # RabbitMQ adapter
│   │   └── redis.py           # Redis adapter
│   ├── api.py                 # Streaming API endpoints
│   └── admin.py               # Admin API endpoints
├── modules/
│   └── webhook_connect.py     # WebhookConnectModule
├── connector/
│   ├── __init__.py
│   ├── main.py                # Connector entry point
│   ├── config.py              # Configuration handling
│   ├── stream_client.py       # WebSocket client
│   └── message_processor.py   # Message processing

tests/
├── unit/
│   ├── test_channel_manager.py
│   ├── test_buffer_rabbitmq.py
│   ├── test_buffer_redis.py
│   ├── test_stream_client.py
│   └── test_message_processor.py
├── integration/
│   ├── test_end_to_end.py
│   ├── test_reconnection.py
│   └── test_token_rotation.py
└── performance/
    └── test_throughput.py
```

### 15.2 Dependencies

**Cloud Receiver (additional):**
```
aio-pika>=9.0.0        # RabbitMQ async client
redis>=5.0.0           # Redis async client
websockets>=12.0       # WebSocket server
```

**Local Connector:**
```
websockets>=12.0       # WebSocket client
click>=8.0.0           # CLI framework
# Plus existing module dependencies (kafka-python, asyncpg, etc.)
```

---

*End of Software Requirements Specification*
