"""
Admin API for Webhook Connect.

Provides administrative endpoints for managing channels,
viewing statistics, and monitoring connections.
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel

from src.webhook_connect.channel_manager import ChannelManager
from src.webhook_connect.models import ChannelStats

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/webhook-connect", tags=["Webhook Connect Admin"])

# Admin token from environment
ADMIN_TOKEN = os.environ.get("WEBHOOK_CONNECT_ADMIN_TOKEN", "")

# Global channel manager reference
_channel_manager: Optional[ChannelManager] = None


def set_channel_manager(manager: ChannelManager) -> None:
    """Set the global channel manager instance."""
    global _channel_manager
    _channel_manager = manager


def get_channel_manager() -> ChannelManager:
    """Get the global channel manager instance."""
    if _channel_manager is None:
        raise HTTPException(status_code=503, detail="Webhook Connect not initialized")
    return _channel_manager


async def verify_admin_token(authorization: str = Header(None)) -> bool:
    """Verify admin authorization token."""
    if not ADMIN_TOKEN:
        # No token configured, admin API is disabled
        raise HTTPException(
            status_code=403,
            detail="Admin API disabled. Set WEBHOOK_CONNECT_ADMIN_TOKEN environment variable.",
        )

    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    token = authorization.replace("Bearer ", "").strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")

    return True


# Pydantic models for request/response


class ChannelInfo(BaseModel):
    """Channel information response."""

    name: str
    webhook_id: str
    created_at: str
    ttl_seconds: int
    max_queue_size: int
    max_connections: int
    connected_clients: int


class ChannelDetailResponse(BaseModel):
    """Detailed channel response."""

    name: str
    webhook_id: str
    created_at: str
    config: dict
    stats: dict
    connected_clients: list


class RotateTokenRequest(BaseModel):
    """Token rotation request."""

    grace_period_seconds: int = 3600


class RotateTokenResponse(BaseModel):
    """Token rotation response."""

    channel: str
    new_token: str
    old_token_expires_at: str
    message: str


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    buffer: bool
    channels_count: int
    connections_count: int
    timestamp: str


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Check health of Webhook Connect system.

    Returns health status of buffer connection and component counts.
    """
    channel_manager = get_channel_manager()
    health = await channel_manager.health_check()

    status = "healthy" if health.get("buffer", False) else "unhealthy"

    return HealthResponse(
        status=status,
        buffer=health.get("buffer", False),
        channels_count=health.get("channels_count", 0),
        connections_count=health.get("connections_count", 0),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/channels", response_model=List[ChannelInfo])
async def list_channels(_: bool = Depends(verify_admin_token)):
    """
    List all registered channels.

    Returns summary information for each channel.
    """
    channel_manager = get_channel_manager()
    channels = []

    for name in channel_manager.list_channels():
        config = channel_manager.get_channel(name)
        if config:
            connected = len(channel_manager.get_channel_connections(name))
            channels.append(
                ChannelInfo(
                    name=name,
                    webhook_id=config.webhook_id,
                    created_at=config.created_at.isoformat(),
                    ttl_seconds=int(config.ttl.total_seconds()),
                    max_queue_size=config.max_queue_size,
                    max_connections=config.max_connections,
                    connected_clients=connected,
                )
            )

    return channels


@router.get("/channels/{channel}", response_model=ChannelDetailResponse)
async def get_channel_details(channel: str, _: bool = Depends(verify_admin_token)):
    """
    Get detailed information about a channel.

    Includes configuration, statistics, and connected clients.
    """
    channel_manager = get_channel_manager()

    config = channel_manager.get_channel(channel)
    if not config:
        raise HTTPException(status_code=404, detail="Channel not found")

    stats = await channel_manager.get_channel_stats(channel)
    connections = channel_manager.get_channel_connections(channel)

    return ChannelDetailResponse(
        name=channel,
        webhook_id=config.webhook_id,
        created_at=config.created_at.isoformat(),
        config=config.to_dict(),
        stats=stats.to_dict() if stats else {},
        connected_clients=[conn.to_dict() for conn in connections],
    )


@router.post("/channels/{channel}/rotate-token", response_model=RotateTokenResponse)
async def rotate_channel_token(
    channel: str, request: RotateTokenRequest, _: bool = Depends(verify_admin_token)
):
    """
    Rotate channel authentication token.

    The old token remains valid for the specified grace period,
    allowing connectors time to update their configuration.
    """
    channel_manager = get_channel_manager()

    config = channel_manager.get_channel(channel)
    if not config:
        raise HTTPException(status_code=404, detail="Channel not found")

    grace_period = timedelta(seconds=request.grace_period_seconds)
    new_token = await channel_manager.rotate_token(channel, grace_period)

    if not new_token:
        raise HTTPException(status_code=500, detail="Failed to rotate token")

    expires_at = datetime.now(timezone.utc) + grace_period

    return RotateTokenResponse(
        channel=channel,
        new_token=new_token,
        old_token_expires_at=expires_at.isoformat(),
        message=f"Old token valid for {request.grace_period_seconds} seconds grace period",
    )


@router.delete("/channels/{channel}/connections/{connection_id}")
async def disconnect_connection(
    channel: str, connection_id: str, _: bool = Depends(verify_admin_token)
):
    """
    Forcefully disconnect a connector.

    The connector will need to reconnect.
    """
    channel_manager = get_channel_manager()

    connection = channel_manager.get_connection(connection_id)
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")

    if connection.channel != channel:
        raise HTTPException(status_code=400, detail="Connection not on this channel")

    await channel_manager.remove_connection(connection_id)

    return {"status": "disconnected", "connection_id": connection_id}


@router.get("/channels/{channel}/stats")
async def get_channel_stats(channel: str, _: bool = Depends(verify_admin_token)):
    """
    Get channel statistics.

    Returns queue depth, in-flight messages, delivery counts, etc.
    """
    channel_manager = get_channel_manager()

    stats = await channel_manager.get_channel_stats(channel)
    if not stats:
        raise HTTPException(status_code=404, detail="Channel not found")

    return stats.to_dict()


@router.get("/channels/{channel}/dead-letters")
async def get_dead_letters(
    channel: str, limit: int = 100, _: bool = Depends(verify_admin_token)
):
    """
    Get dead letter messages for a channel.

    Dead letters are messages that failed processing and were not retried.
    """
    channel_manager = get_channel_manager()

    if not channel_manager.get_channel(channel):
        raise HTTPException(status_code=404, detail="Channel not found")

    messages = await channel_manager.buffer.get_dead_letters(channel, limit)

    return {
        "channel": channel,
        "count": len(messages),
        "messages": [msg.to_envelope() for msg in messages],
    }


@router.get("/overview")
async def get_overview(_: bool = Depends(verify_admin_token)):
    """
    Get overview of all Webhook Connect activity.

    Returns summary of all channels and their current state.
    """
    channel_manager = get_channel_manager()

    channels_summary = channel_manager.get_all_stats()
    health = await channel_manager.health_check()

    total_connections = sum(
        c.get("connected_clients", 0) for c in channels_summary.values()
    )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "health": health,
        "total_channels": len(channels_summary),
        "total_connections": total_connections,
        "channels": channels_summary,
    }
