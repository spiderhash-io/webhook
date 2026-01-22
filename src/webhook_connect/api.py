"""
Streaming API for Webhook Connect.

Provides WebSocket and Server-Sent Events (SSE) endpoints for
Local Connectors to receive webhook messages from the Cloud Receiver.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Callable, Awaitable

from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Header,
    Query,
)
from fastapi.responses import StreamingResponse
from starlette.websockets import WebSocketState

from src.webhook_connect.models import (
    ConnectorConnection,
    ConnectionProtocol,
    ConnectionState,
    WebhookMessage,
    MessageAck,
    AckStatus,
)
from src.webhook_connect.channel_manager import ChannelManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/connect", tags=["Webhook Connect"])

# Global channel manager reference (set during app startup)
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


@router.websocket("/stream/{channel}")
async def websocket_stream(
    websocket: WebSocket,
    channel: str,
):
    """
    WebSocket endpoint for streaming webhooks to Local Connector.

    The connector must provide authentication via:
    - Authorization header: Bearer {channel_token}
    - Or query parameter: ?token={channel_token}

    Message Protocol:
    - Server sends: {"type": "webhook", "message_id": "...", "data": {...}}
    - Server sends: {"type": "heartbeat", "timestamp": "..."}
    - Client sends: {"type": "ack", "message_id": "..."}
    - Client sends: {"type": "nack", "message_id": "...", "retry": true/false}
    """
    channel_manager = get_channel_manager()

    # Extract authentication token
    auth_header = websocket.headers.get("authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    if not token:
        token = websocket.query_params.get("token", "")

    # Validate token
    if not channel_manager.validate_token(channel, token):
        await websocket.close(code=4001, reason="Invalid channel token")
        logger.warning(
            f"WebSocket connection rejected: invalid token for channel {channel}"
        )
        return

    # Check if channel exists
    channel_config = channel_manager.get_channel(channel)
    if not channel_config:
        await websocket.close(code=4002, reason="Channel not found")
        logger.warning(f"WebSocket connection rejected: channel {channel} not found")
        return

    # Accept connection
    await websocket.accept()

    # Create connection record
    connector_id = websocket.headers.get("x-connector-id", f"ws_{id(websocket)}")
    connection = ConnectorConnection(
        connection_id=f"wsc_{id(websocket)}_{datetime.now(timezone.utc).timestamp():.0f}",
        connector_id=connector_id,
        channel=channel,
        protocol=ConnectionProtocol.WEBSOCKET,
        remote_ip=websocket.client.host if websocket.client else None,
        user_agent=websocket.headers.get("user-agent"),
    )

    # Register connection
    if not await channel_manager.add_connection(connection):
        await websocket.close(code=4003, reason="Max connections reached")
        logger.warning(
            f"WebSocket connection rejected: max connections for channel {channel}"
        )
        return

    logger.info(
        f"WebSocket connection established: {connection.connection_id} for channel {channel}"
    )

    try:
        # Send connected message
        await websocket.send_json(
            {
                "type": "connected",
                "connection_id": connection.connection_id,
                "channel": channel,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        # Start message streaming and client message handling
        await asyncio.gather(
            _stream_messages_ws(websocket, channel, connection, channel_manager),
            _handle_client_messages_ws(websocket, channel, connection, channel_manager),
            _send_heartbeats_ws(
                websocket, connection, channel_config.heartbeat_interval.total_seconds()
            ),
        )

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {connection.connection_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        connection.state = ConnectionState.DISCONNECTED
        await channel_manager.remove_connection(connection.connection_id)
        logger.info(f"WebSocket connection cleaned up: {connection.connection_id}")


async def _stream_messages_ws(
    websocket: WebSocket,
    channel: str,
    connection: ConnectorConnection,
    channel_manager: ChannelManager,
) -> None:
    """Stream messages from buffer to WebSocket."""
    channel_config = channel_manager.get_channel(channel)
    if not channel_config:
        return

    buffer = channel_manager.buffer

    async def send_message(message: WebhookMessage) -> None:
        """Callback to send message to WebSocket."""
        # Check WebSocket state first
        if websocket.client_state != WebSocketState.CONNECTED:
            raise Exception("WebSocket disconnected")

        # Check in-flight limit
        while len(connection.in_flight_messages) >= channel_config.max_in_flight:
            if websocket.client_state != WebSocketState.CONNECTED:
                raise Exception("WebSocket disconnected")
            await asyncio.sleep(0.1)  # Backpressure

        # Final check before sending
        if websocket.client_state != WebSocketState.CONNECTED:
            raise Exception("WebSocket disconnected")

        # Track in-flight
        connection.in_flight_messages.add(message.message_id)
        message.delivery_count += 1
        message.last_delivered_to = connection.connection_id
        message.last_delivered_at = datetime.now(timezone.utc)

        try:
            # Send to client
            await websocket.send_json(message.to_wire_format())
            connection.messages_received += 1
            connection.last_message_at = datetime.now(timezone.utc)
            logger.debug(
                f"Sent message {message.message_id} to {connection.connection_id}"
            )
        except Exception as e:
            # Remove from in-flight on send failure
            connection.in_flight_messages.discard(message.message_id)
            raise

    try:
        # Subscribe to channel and stream messages
        await buffer.subscribe(channel, send_message)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error streaming messages: {e}")


async def _handle_client_messages_ws(
    websocket: WebSocket,
    channel: str,
    connection: ConnectorConnection,
    channel_manager: ChannelManager,
) -> None:
    """Handle ACK/NACK messages from WebSocket client."""
    while websocket.client_state == WebSocketState.CONNECTED:
        try:
            data = await websocket.receive_json()
            msg_type = data.get("type")

            if msg_type == "ack":
                message_id = data.get("message_id")
                if message_id and message_id in connection.in_flight_messages:
                    await channel_manager.ack_message(
                        channel, message_id, connection.connection_id
                    )
                    logger.debug(f"ACK received for {message_id}")

            elif msg_type == "nack":
                message_id = data.get("message_id")
                retry = data.get("retry", True)
                if message_id and message_id in connection.in_flight_messages:
                    await channel_manager.nack_message(
                        channel, message_id, connection.connection_id, retry=retry
                    )
                    logger.debug(f"NACK received for {message_id}, retry={retry}")

            elif msg_type == "heartbeat":
                connection.last_heartbeat_at = datetime.now(timezone.utc)

        except WebSocketDisconnect:
            break
        except Exception as e:
            logger.error(f"Error handling client message: {e}")
            break


async def _send_heartbeats_ws(
    websocket: WebSocket, connection: ConnectorConnection, interval_seconds: float
) -> None:
    """Send periodic heartbeats to WebSocket client."""
    while websocket.client_state == WebSocketState.CONNECTED:
        try:
            await asyncio.sleep(interval_seconds)
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_json(
                    {
                        "type": "heartbeat",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "server_time": datetime.now(timezone.utc).isoformat(),
                    }
                )
        except Exception:
            break


@router.get("/stream/{channel}/sse")
async def sse_stream(
    channel: str,
    authorization: str = Header(None),
    token: str = Query(None),
    x_connector_id: str = Header("sse_default"),
):
    """
    Server-Sent Events endpoint for streaming webhooks.

    This is a fallback for clients that don't support WebSocket.
    ACKs must be sent via the POST /connect/ack endpoint.

    Event types:
    - connected: Connection established
    - webhook: Webhook message to process
    - heartbeat: Keep-alive ping
    - error: Error notification
    """
    channel_manager = get_channel_manager()

    # Extract authentication token
    auth_token = token
    if authorization:
        auth_token = authorization.replace("Bearer ", "").strip()

    if not auth_token:
        raise HTTPException(status_code=401, detail="Missing authorization token")

    # Validate token
    if not channel_manager.validate_token(channel, auth_token):
        raise HTTPException(status_code=401, detail="Invalid channel token")

    # Check if channel exists
    channel_config = channel_manager.get_channel(channel)
    if not channel_config:
        raise HTTPException(status_code=404, detail="Channel not found")

    async def event_generator():
        """Generate SSE events."""
        # Create connection record
        connection = ConnectorConnection(
            connection_id=f"sse_{id(event_generator)}_{datetime.now(timezone.utc).timestamp():.0f}",
            connector_id=x_connector_id,
            channel=channel,
            protocol=ConnectionProtocol.SSE,
        )

        # Register connection
        if not await channel_manager.add_connection(connection):
            yield f'event: error\ndata: {{"error": "max_connections_reached"}}\n\n'
            return

        try:
            # Send connected event
            yield f"event: connected\ndata: {json.dumps({'connection_id': connection.connection_id, 'channel': channel})}\n\n"

            buffer = channel_manager.buffer

            async def send_message(message: WebhookMessage) -> None:
                """This won't be used directly - SSE needs different handling."""
                pass

            # For SSE, we need to poll/iterate differently
            # Since subscribe is blocking, we use a different approach
            while True:
                # Get pending messages
                # Note: This is a simplified implementation
                # A production version would use proper async iteration
                await asyncio.sleep(0.5)

                # Send heartbeat periodically
                yield f"event: heartbeat\ndata: {json.dumps({'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"SSE stream error for connection {connection.connection_id}: {e}")
            yield f"event: error\ndata: {json.dumps({'error': 'Internal server error'})}\n\n"
        finally:
            await channel_manager.remove_connection(connection.connection_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.post("/ack")
async def acknowledge_message(
    message_id: str,
    status: str = "ack",  # "ack" or "nack"
    retry: bool = True,
    x_connection_id: str = Header(...),
    authorization: str = Header(...),
):
    """
    Acknowledge message processing (for SSE connections).

    Since SSE is unidirectional, ACKs must be sent via this endpoint.
    """
    channel_manager = get_channel_manager()

    # Get connection
    connection = channel_manager.get_connection(x_connection_id)
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")

    # Verify token matches channel
    token = authorization.replace("Bearer ", "").strip()
    if not channel_manager.validate_token(connection.channel, token):
        raise HTTPException(status_code=401, detail="Invalid token")

    # Process ACK/NACK
    if message_id not in connection.in_flight_messages:
        raise HTTPException(status_code=404, detail="Message not in flight")

    if status == "ack":
        success = await channel_manager.ack_message(
            connection.channel, message_id, x_connection_id
        )
    else:
        success = await channel_manager.nack_message(
            connection.channel, message_id, x_connection_id, retry=retry
        )

    if not success:
        raise HTTPException(status_code=500, detail="Failed to process acknowledgment")

    return {"status": "ok", "message_id": message_id}


@router.get("/status/{channel}")
async def get_connection_status(
    channel: str,
    authorization: str = Header(...),
):
    """
    Get channel connection status.

    Useful for connectors to check their connection health.
    """
    channel_manager = get_channel_manager()

    # Verify token
    token = authorization.replace("Bearer ", "").strip()
    if not channel_manager.validate_token(channel, token):
        raise HTTPException(status_code=401, detail="Invalid token")

    stats = await channel_manager.get_channel_stats(channel)
    if not stats:
        raise HTTPException(status_code=404, detail="Channel not found")

    return {
        "channel": channel,
        "connected": True,
        "stats": stats.to_dict(),
        "server_time": datetime.now(timezone.utc).isoformat(),
    }
