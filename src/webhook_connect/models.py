"""
Data models for Webhook Connect.

This module defines the core data structures used throughout the webhook connect system:
- WebhookMessage: A webhook message in the channel queue
- ChannelConfig: Configuration for a webhook connect channel
- ConnectorConnection: An active connector connection
- MessageAck: Acknowledgment from connector
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Set, List
from datetime import datetime, timedelta, timezone
from enum import Enum
import hmac
import uuid


class ConnectionProtocol(Enum):
    """Protocol used by connector to receive messages."""
    WEBSOCKET = "websocket"
    SSE = "sse"
    LONG_POLL = "long_poll"


class ConnectionState(Enum):
    """State of a connector connection."""
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"


class AckStatus(Enum):
    """Status of message acknowledgment."""
    ACK = "ack"              # Successfully processed
    NACK_RETRY = "nack_retry"      # Failed, should retry
    NACK_REJECT = "nack_reject"    # Failed, don't retry (dead letter)


class MessageState(Enum):
    """State of a message in the queue."""
    PENDING = "pending"           # Waiting to be delivered
    IN_FLIGHT = "in_flight"       # Delivered, waiting for ACK
    DELIVERED = "delivered"       # Successfully acknowledged
    EXPIRED = "expired"           # TTL exceeded
    DEAD_LETTERED = "dead_lettered"  # Permanently failed


@dataclass
class ChannelConfig:
    """Configuration for a webhook connect channel."""

    name: str                           # Unique channel identifier
    webhook_id: str                     # Associated webhook endpoint ID
    channel_token: str                  # Authentication token for connectors

    # Queue settings
    ttl: timedelta = field(default_factory=lambda: timedelta(hours=24))
    max_queue_size: int = 10000               # Maximum messages in queue
    max_message_size: int = 10 * 1024 * 1024  # 10MB max payload

    # Delivery settings
    max_in_flight: int = 100            # Max unacknowledged messages per client
    ack_timeout: timedelta = field(default_factory=lambda: timedelta(seconds=30))

    # Connection settings
    max_connections: int = 10           # Max concurrent connectors
    heartbeat_interval: timedelta = field(default_factory=lambda: timedelta(seconds=30))

    # Optional settings
    allowed_ips: Optional[List[str]] = None  # IP allowlist
    rate_limit_per_second: Optional[int] = None

    # Token rotation support
    old_token: Optional[str] = None
    old_token_expires_at: Optional[datetime] = None

    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def validate_token(self, token: str) -> bool:
        """
        Validate a channel access token.

        Uses constant-time comparison to prevent timing attacks.
        Supports token rotation with grace period.
        """
        if not token:
            return False

        # Check current token using constant-time comparison
        if hmac.compare_digest(token, self.channel_token):
            return True

        # Check old token during grace period
        if self.old_token and self.old_token_expires_at:
            if datetime.now(timezone.utc) < self.old_token_expires_at:
                if hmac.compare_digest(token, self.old_token):
                    return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "webhook_id": self.webhook_id,
            "ttl_seconds": int(self.ttl.total_seconds()),
            "max_queue_size": self.max_queue_size,
            "max_message_size": self.max_message_size,
            "max_in_flight": self.max_in_flight,
            "ack_timeout_seconds": int(self.ack_timeout.total_seconds()),
            "max_connections": self.max_connections,
            "heartbeat_interval_seconds": int(self.heartbeat_interval.total_seconds()),
            "allowed_ips": self.allowed_ips,
            "rate_limit_per_second": self.rate_limit_per_second,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class WebhookMessage:
    """A webhook message in the channel queue."""

    message_id: str = field(default_factory=lambda: f"msg_{uuid.uuid4().hex[:16]}")
    channel: str = ""
    webhook_id: str = ""

    # Timing
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
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
    state: MessageState = MessageState.PENDING

    # Internal tracking (not serialized to wire)
    _buffer_id: Optional[str] = field(default=None, repr=False)

    def is_expired(self) -> bool:
        """Check if message has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_wire_format(self) -> Dict[str, Any]:
        """Format for WebSocket/SSE transmission to connector."""
        return {
            "type": "webhook",
            "message_id": self.message_id,
            "sequence": self.sequence,
            "webhook_id": self.webhook_id,
            "timestamp": self.received_at.isoformat(),
            "headers": self.headers,
            "payload": self.payload
        }

    def to_envelope(self) -> Dict[str, Any]:
        """Full envelope format for queue storage."""
        return {
            "message_id": self.message_id,
            "channel": self.channel,
            "webhook_id": self.webhook_id,
            "timestamp": self.received_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata,
            "headers": self.headers,
            "payload": self.payload,
            "sequence": self.sequence,
            "delivery_count": self.delivery_count,
            "state": self.state.value,
        }

    @classmethod
    def from_envelope(cls, data: Dict[str, Any]) -> "WebhookMessage":
        """Create message from envelope format."""
        return cls(
            message_id=data.get("message_id", f"msg_{uuid.uuid4().hex[:16]}"),
            channel=data.get("channel", ""),
            webhook_id=data.get("webhook_id", ""),
            received_at=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else datetime.now(timezone.utc),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            metadata=data.get("metadata", {}),
            headers=data.get("headers", {}),
            payload=data.get("payload"),
            sequence=data.get("sequence", 0),
            delivery_count=data.get("delivery_count", 0),
            state=MessageState(data.get("state", "pending")),
        )


@dataclass
class ConnectorConnection:
    """An active connector connection."""

    connection_id: str
    connector_id: str                    # Client-provided identifier
    channel: str
    protocol: ConnectionProtocol

    # Timing
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
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

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "connection_id": self.connection_id,
            "connector_id": self.connector_id,
            "channel": self.channel,
            "protocol": self.protocol.value,
            "connected_at": self.connected_at.isoformat(),
            "last_heartbeat_at": self.last_heartbeat_at.isoformat() if self.last_heartbeat_at else None,
            "last_message_at": self.last_message_at.isoformat() if self.last_message_at else None,
            "state": self.state.value,
            "in_flight_count": len(self.in_flight_messages),
            "messages_received": self.messages_received,
            "messages_acked": self.messages_acked,
            "messages_nacked": self.messages_nacked,
            "remote_ip": self.remote_ip,
        }


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

    @classmethod
    def from_dict(cls, data: Dict[str, Any], connection_id: str) -> "MessageAck":
        """Create from client message."""
        status_str = data.get("type", "ack")
        if status_str == "ack":
            status = AckStatus.ACK
        elif data.get("retry", True):
            status = AckStatus.NACK_RETRY
        else:
            status = AckStatus.NACK_REJECT

        return cls(
            message_id=data.get("message_id", ""),
            status=status,
            processed_at=datetime.fromisoformat(data["processed_at"])
                if data.get("processed_at") else datetime.now(timezone.utc),
            connection_id=connection_id,
            error_code=data.get("error_code"),
            error_message=data.get("error") or data.get("message"),
        )


@dataclass
class ChannelStats:
    """Statistics for a channel."""

    channel: str
    messages_queued: int = 0
    messages_in_flight: int = 0
    messages_delivered: int = 0
    messages_expired: int = 0
    messages_dead_lettered: int = 0
    connected_clients: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "channel": self.channel,
            "messages_queued": self.messages_queued,
            "messages_in_flight": self.messages_in_flight,
            "messages_delivered": self.messages_delivered,
            "messages_expired": self.messages_expired,
            "messages_dead_lettered": self.messages_dead_lettered,
            "connected_clients": self.connected_clients,
        }
