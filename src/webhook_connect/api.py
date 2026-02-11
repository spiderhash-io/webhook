"""
Streaming API for Webhook Connect.

Provides WebSocket and Server-Sent Events (SSE) endpoints for
Local Connectors to receive webhook messages from the Cloud Receiver.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Header,
    Query,
)
from fastapi.responses import StreamingResponse, Response
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

    # Set initial heartbeat baseline for eviction tracking
    connection.last_heartbeat_at = datetime.now(timezone.utc)

    # Register per-connection send function for deferred consumption delivery
    async def _ws_send(message: WebhookMessage) -> None:
        """Send message to this WebSocket connection."""
        if websocket.client_state != WebSocketState.CONNECTED:
            raise Exception("WebSocket disconnected")

        # Backpressure: wait for in-flight to drop below limit
        while len(connection.in_flight_messages) >= channel_config.max_in_flight:
            if websocket.client_state != WebSocketState.CONNECTED:
                raise Exception("WebSocket disconnected")
            await asyncio.sleep(0.1)

        if websocket.client_state != WebSocketState.CONNECTED:
            raise Exception("WebSocket disconnected")

        # Track in-flight
        connection.in_flight_messages.add(message.message_id)
        message.delivery_count += 1
        message.last_delivered_to = connection.connection_id
        message.last_delivered_at = datetime.now(timezone.utc)

        try:
            await websocket.send_json(message.to_wire_format())
            connection.messages_received += 1
            connection.last_message_at = datetime.now(timezone.utc)
            logger.debug(
                f"Sent message {message.message_id} to {connection.connection_id}"
            )
        except Exception:
            connection.in_flight_messages.discard(message.message_id)
            raise

    channel_manager.register_send_fn(connection.connection_id, _ws_send)

    # Register connection (starts buffer consumer on first client)
    if not await channel_manager.add_connection(connection):
        # Connection was rejected; remove pre-registered callback to avoid leaks.
        channel_manager.unregister_send_fn(connection.connection_id)
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
    """
    Wait for WebSocket closure.

    Messages are delivered via channel_manager's deferred consumption
    callback (started in add_connection, stopped in remove_connection).
    This coroutine just keeps the gather() alive while the WebSocket
    is open.
    """
    try:
        while websocket.client_state == WebSocketState.CONNECTED:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass


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
        # Set initial heartbeat baseline for eviction tracking
        connection.last_heartbeat_at = datetime.now(timezone.utc)

        # Register connection
        if not await channel_manager.add_connection(connection):
            yield 'event: error\ndata: {"error": "max_connections_reached"}\n\n'
            return

        # Create message queue for SSE delivery
        message_queue: asyncio.Queue[WebhookMessage] = asyncio.Queue()

        # Register per-connection send function for deferred consumption
        async def _sse_send(message: WebhookMessage) -> None:
            """Send message to SSE queue for delivery."""
            # Backpressure
            while len(connection.in_flight_messages) >= channel_config.max_in_flight:
                await asyncio.sleep(0.1)

            connection.in_flight_messages.add(message.message_id)
            message.delivery_count += 1
            message.last_delivered_to = connection.connection_id
            message.last_delivered_at = datetime.now(timezone.utc)

            await message_queue.put(message)

        channel_manager.register_send_fn(connection.connection_id, _sse_send)

        try:
            # Send connected event
            connected_data = {"connection_id": connection.connection_id, "channel": channel}
            yield f"event: connected\ndata: {json.dumps(connected_data)}\n\n"

            # Heartbeat interval from channel config
            heartbeat_interval = channel_config.heartbeat_interval.total_seconds()
            last_heartbeat = datetime.now(timezone.utc)

            while True:
                try:
                    # Check for messages with short timeout to allow heartbeats
                    message = await asyncio.wait_for(
                        message_queue.get(), timeout=0.5
                    )

                    # Format and yield webhook message
                    connection.messages_received += 1
                    connection.last_message_at = datetime.now(timezone.utc)

                    yield f"event: webhook\ndata: {json.dumps(message.to_wire_format())}\n\n"
                    logger.debug(
                        f"SSE sent message {message.message_id} to {connection.connection_id}"
                    )

                except asyncio.TimeoutError:
                    # No message available, check if heartbeat needed
                    now = datetime.now(timezone.utc)
                    elapsed = (now - last_heartbeat).total_seconds()

                    if elapsed >= heartbeat_interval:
                        hb_data = {"timestamp": now.isoformat()}
                        yield f"event: heartbeat\ndata: {json.dumps(hb_data)}\n\n"
                        last_heartbeat = now

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


@router.get("/stream/{channel}/poll")
async def long_poll_stream(
    channel: str,
    timeout: int = Query(default=30, ge=1, le=60, description="Timeout in seconds"),
    max_messages: int = Query(default=10, ge=1, le=100, description="Max messages to return"),
    authorization: str = Header(None),
    token: str = Query(None),
    x_connector_id: str = Header("poll_default"),
):
    """
    Long-polling endpoint for streaming webhooks.

    This is a fallback for environments where WebSocket and SSE are unavailable.
    Returns messages immediately when available, or after timeout with empty response.

    Response:
    - 200: Messages available, returns {"messages": [...], "connection_id": "..."}
    - 204: No messages available within timeout
    - 401: Invalid authentication
    - 404: Channel not found

    ACKs must be sent via the POST /connect/ack endpoint using the connection_id.
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

    # Create connection record
    connection = ConnectorConnection(
        connection_id=f"poll_{x_connector_id}_{datetime.now(timezone.utc).timestamp():.0f}",
        connector_id=x_connector_id,
        channel=channel,
        protocol=ConnectionProtocol.LONG_POLL,
    )
    # Set initial heartbeat baseline for eviction tracking
    connection.last_heartbeat_at = datetime.now(timezone.utc)

    # Register connection
    if not await channel_manager.add_connection(connection):
        raise HTTPException(status_code=503, detail="Max connections reached")

    # Create message queue for collection
    message_queue: asyncio.Queue[WebhookMessage] = asyncio.Queue()
    collected_messages: list = []

    # Register per-connection send function for deferred consumption
    async def _poll_send(message: WebhookMessage) -> None:
        """Collect messages for long-poll response."""
        connection.in_flight_messages.add(message.message_id)
        message.delivery_count += 1
        message.last_delivered_to = connection.connection_id
        message.last_delivered_at = datetime.now(timezone.utc)

        await message_queue.put(message)

    channel_manager.register_send_fn(connection.connection_id, _poll_send)

    try:
        # Collect messages until timeout or max_messages reached
        start_time = datetime.now(timezone.utc)
        remaining_timeout = float(timeout)

        while len(collected_messages) < max_messages and remaining_timeout > 0:
            try:
                message = await asyncio.wait_for(
                    message_queue.get(), timeout=min(remaining_timeout, 1.0)
                )
                collected_messages.append(message)
                connection.messages_received += 1
                connection.last_message_at = datetime.now(timezone.utc)

                # If we got at least one message, return immediately
                if len(collected_messages) >= 1:
                    break

            except asyncio.TimeoutError:
                # Update remaining timeout
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                remaining_timeout = timeout - elapsed

        if not collected_messages:
            # No messages within timeout - return 204
            await channel_manager.remove_connection(connection.connection_id)
            return Response(status_code=204)

        # Return collected messages
        await channel_manager.remove_connection(connection.connection_id)
        return {
            "messages": [msg.to_wire_format() for msg in collected_messages],
            "connection_id": connection.connection_id,
            "channel": channel,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Long-poll error for channel {channel}: {e}")
        await channel_manager.remove_connection(connection.connection_id)
        raise HTTPException(status_code=500, detail="Internal server error")


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
