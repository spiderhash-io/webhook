"""
Stream Client for Local Connector.

Handles WebSocket and SSE connections to the Cloud Receiver.
Provides automatic reconnection with exponential backoff.
"""

import asyncio
import json
import logging
import random
import ssl
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable, Awaitable, Dict, Any

import aiohttp
from aiohttp import ClientSession, WSMsgType

from src.connector.config import ConnectorConfig

logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Connection state enumeration."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    CLOSING = "closing"
    CLOSED = "closed"


class StreamClient(ABC):
    """Abstract base class for stream clients."""

    def __init__(
        self,
        config: ConnectorConfig,
        on_message: Callable[[Dict[str, Any]], Awaitable[None]],
        on_connect: Optional[Callable[[], Awaitable[None]]] = None,
        on_disconnect: Optional[
            Callable[[Optional[Exception]], Awaitable[None]]
        ] = None,
    ):
        """
        Initialize stream client.

        Args:
            config: Connector configuration
            on_message: Callback for received messages
            on_connect: Optional callback when connected
            on_disconnect: Optional callback when disconnected
        """
        self.config = config
        self.on_message = on_message
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect

        self.state = ConnectionState.DISCONNECTED
        self.connection_id: Optional[str] = None
        self.last_heartbeat: Optional[datetime] = None
        self._reconnect_delay = config.reconnect_delay
        self._stop_event = asyncio.Event()
        self._session: Optional[ClientSession] = None

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the server."""
        pass

    @abstractmethod
    async def send_ack(self, message_id: str) -> bool:
        """Send acknowledgment for a message."""
        pass

    @abstractmethod
    async def send_nack(self, message_id: str, retry: bool = True) -> bool:
        """Send negative acknowledgment for a message."""
        pass

    async def start(self) -> None:
        """Start the client with automatic reconnection."""
        self._stop_event.clear()
        self._reconnect_delay = self.config.reconnect_delay

        while not self._stop_event.is_set():
            try:
                self.state = ConnectionState.CONNECTING
                await self.connect()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Connection error: {e}")
                if self.on_disconnect:
                    await self.on_disconnect(e)

            if self._stop_event.is_set():
                break

            # Reconnect with exponential backoff + jitter
            self.state = ConnectionState.RECONNECTING
            jitter = random.uniform(0, self._reconnect_delay * 0.3)
            delay = self._reconnect_delay + jitter
            logger.info(f"Reconnecting in {delay:.1f} seconds...")
            await asyncio.sleep(delay)

            self._reconnect_delay = min(
                self._reconnect_delay * self.config.reconnect_backoff_multiplier,
                self.config.max_reconnect_delay,
            )

        self.state = ConnectionState.CLOSED

    async def stop(self) -> None:
        """Stop the client."""
        self.state = ConnectionState.CLOSING
        self._stop_event.set()
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def _create_ssl_context(self) -> "Optional[ssl.SSLContext | bool]":
        """Create SSL context from configuration.

        Returns:
            ssl.SSLContext for custom certs, False to disable verification,
            or None to use system defaults.
        """
        if not self.config.verify_ssl:
            return False  # Disable SSL verification

        if self.config.ca_cert_path or self.config.client_cert_path:
            ctx = ssl.create_default_context()

            if self.config.ca_cert_path:
                ctx.load_verify_locations(self.config.ca_cert_path)

            if self.config.client_cert_path:
                ctx.load_cert_chain(
                    self.config.client_cert_path, self.config.client_key_path
                )

            return ctx

        return None  # Use default SSL context

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for connection."""
        headers = {
            "Authorization": f"Bearer {self.config.token}",
        }
        if self.config.connector_id:
            headers["X-Connector-ID"] = self.config.connector_id
        return headers


class WebSocketClient(StreamClient):
    """WebSocket-based stream client."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        """Establish WebSocket connection."""
        url = self.config.get_stream_url()
        ssl_context = self._create_ssl_context()

        async with aiohttp.ClientSession() as session:
            self._session = session
            try:
                async with session.ws_connect(
                    url,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=self.config.connection_timeout),
                    ssl=ssl_context,
                    heartbeat=self.config.heartbeat_timeout,
                ) as ws:
                    self._ws = ws
                    self.state = ConnectionState.CONNECTED
                    self._reconnect_delay = self.config.reconnect_delay
                    logger.info(f"WebSocket connected to {url}")

                    if self.on_connect:
                        await self.on_connect()

                    # Start heartbeat monitor
                    self._heartbeat_task = asyncio.create_task(
                        self._monitor_heartbeat()
                    )

                    # Message loop
                    await self._message_loop()

            except aiohttp.WSServerHandshakeError as e:
                logger.error(f"WebSocket handshake failed: {e}")
                raise
            finally:
                if self._heartbeat_task:
                    self._heartbeat_task.cancel()
                    try:
                        await self._heartbeat_task
                    except asyncio.CancelledError:
                        pass
                self._ws = None

    async def _message_loop(self) -> None:
        """Process incoming WebSocket messages."""
        async for msg in self._ws:
            if self._stop_event.is_set():
                break

            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    await self._handle_message(data)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse message: {e}")
                except Exception as e:
                    logger.error(f"Error handling message: {e}")

            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error: {self._ws.exception()}")
                break

            elif msg.type == WSMsgType.CLOSED:
                logger.info("WebSocket closed by server")
                break

    async def _handle_message(self, data: Dict[str, Any]) -> None:
        """Handle a received message."""
        msg_type = data.get("type")

        if msg_type == "connected":
            self.connection_id = data.get("connection_id")
            logger.info(f"Connected with ID: {self.connection_id}")

        elif msg_type == "heartbeat":
            self.last_heartbeat = datetime.now(timezone.utc)
            logger.debug("Received heartbeat")

        elif msg_type == "webhook":
            # Forward to message handler
            await self.on_message(data)

        else:
            logger.warning(f"Unknown message type: {msg_type}")

    async def _monitor_heartbeat(self) -> None:
        """Monitor heartbeat and reconnect if stale."""
        while not self._stop_event.is_set():
            await asyncio.sleep(self.config.heartbeat_timeout / 2)

            if self.last_heartbeat:
                elapsed = (
                    datetime.now(timezone.utc) - self.last_heartbeat
                ).total_seconds()
                if elapsed > self.config.heartbeat_timeout:
                    logger.warning(
                        f"Heartbeat timeout ({elapsed:.1f}s > {self.config.heartbeat_timeout}s)"
                    )
                    if self._ws:
                        await self._ws.close()
                    break

    async def send_ack(self, message_id: str) -> bool:
        """Send acknowledgment for a message."""
        if not self._ws or self._ws.closed:
            return False

        try:
            await self._ws.send_json({"type": "ack", "message_id": message_id})
            logger.debug(f"Sent ACK for {message_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send ACK: {e}")
            return False

    async def send_nack(self, message_id: str, retry: bool = True) -> bool:
        """Send negative acknowledgment for a message."""
        if not self._ws or self._ws.closed:
            return False

        try:
            await self._ws.send_json(
                {"type": "nack", "message_id": message_id, "retry": retry}
            )
            logger.debug(f"Sent NACK for {message_id}, retry={retry}")
            return True
        except Exception as e:
            logger.error(f"Failed to send NACK: {e}")
            return False


class SSEClient(StreamClient):
    """Server-Sent Events based stream client."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._response: Optional[aiohttp.ClientResponse] = None

    async def connect(self) -> None:
        """Establish SSE connection."""
        url = self.config.get_stream_url()
        ssl_context = self._create_ssl_context()

        headers = self._get_headers()
        headers["Accept"] = "text/event-stream"
        headers["Cache-Control"] = "no-cache"

        session = aiohttp.ClientSession()
        self._session = session

        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=None),  # No timeout for SSE
                ssl=ssl_context,
            ) as response:
                if response.status != 200:
                    raise Exception(
                        f"SSE connection failed with status {response.status}"
                    )

                self._response = response
                self.state = ConnectionState.CONNECTED
                self._reconnect_delay = self.config.reconnect_delay
                logger.info(f"SSE connected to {url}")

                if self.on_connect:
                    await self.on_connect()

                # SSE event loop
                await self._sse_loop(response)

        finally:
            await session.close()
            self._session = None
            self._response = None

    async def _sse_loop(self, response: aiohttp.ClientResponse) -> None:
        """Process SSE events."""
        buffer = ""
        event_type = "message"
        event_data = ""

        async for chunk in response.content.iter_any():
            if self._stop_event.is_set():
                break

            buffer += chunk.decode("utf-8")
            lines = buffer.split("\n")
            buffer = lines.pop()  # Keep incomplete line in buffer

            for line in lines:
                line = line.rstrip("\r")

                if line.startswith("event:"):
                    event_type = line[6:].strip()

                elif line.startswith("data:"):
                    if event_data:
                        event_data += "\n" + line[5:].strip()
                    else:
                        event_data = line[5:].strip()

                elif line == "" and event_data:
                    # End of event
                    try:
                        await self._handle_sse_event(event_type, event_data)
                    except Exception as e:
                        logger.error(f"Error handling SSE event: {e}")
                    event_type = "message"
                    event_data = ""

    async def _handle_sse_event(self, event_type: str, data: str) -> None:
        """Handle an SSE event."""
        if event_type == "heartbeat":
            self.last_heartbeat = datetime.now(timezone.utc)
            logger.debug("Received heartbeat")
            return

        if event_type == "connected":
            try:
                parsed = json.loads(data)
                self.connection_id = parsed.get("connection_id")
                logger.info(f"Connected with ID: {self.connection_id}")
            except json.JSONDecodeError:
                pass
            return

        if event_type == "error":
            logger.error(f"SSE error: {data}")
            return

        if event_type == "webhook":
            try:
                parsed = json.loads(data)
                parsed["type"] = "webhook"  # Ensure type is set
                await self.on_message(parsed)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse webhook data: {e}")

    async def send_ack(self, message_id: str) -> bool:
        """Send acknowledgment via HTTP POST."""
        if not self._session or self._session.closed:
            return False

        # Build ACK URL
        base_url = self.config.cloud_url.rstrip("/")
        ack_url = f"{base_url}/connect/ack"

        try:
            async with self._session.post(
                ack_url,
                params={"message_id": message_id, "status": "ack"},
                headers={
                    "Authorization": f"Bearer {self.config.token}",
                    "X-Connection-ID": self.connection_id or "",
                },
            ) as response:
                if response.status == 200:
                    logger.debug(f"Sent ACK for {message_id}")
                    return True
                else:
                    logger.error(f"ACK failed with status {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send ACK: {e}")
            return False

    async def send_nack(self, message_id: str, retry: bool = True) -> bool:
        """Send negative acknowledgment via HTTP POST."""
        if not self._session or self._session.closed:
            return False

        base_url = self.config.cloud_url.rstrip("/")
        ack_url = f"{base_url}/connect/ack"

        try:
            async with self._session.post(
                ack_url,
                params={
                    "message_id": message_id,
                    "status": "nack",
                    "retry": str(retry).lower(),
                },
                headers={
                    "Authorization": f"Bearer {self.config.token}",
                    "X-Connection-ID": self.connection_id or "",
                },
            ) as response:
                if response.status == 200:
                    logger.debug(f"Sent NACK for {message_id}, retry={retry}")
                    return True
                else:
                    logger.error(f"NACK failed with status {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send NACK: {e}")
            return False


class LongPollClient(StreamClient):
    """Long-polling based stream client.

    Use this for environments where WebSocket and SSE are unavailable.
    Polls the server repeatedly for new messages.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._poll_timeout = 30  # Server-side timeout in seconds
        self._ssl_context = None  # Store SSL context for ACK/NACK requests

    async def connect(self) -> None:
        """Establish long-polling connection."""
        self._ssl_context = self._create_ssl_context()

        session = aiohttp.ClientSession()
        self._session = session

        try:
            self.state = ConnectionState.CONNECTED
            self._reconnect_delay = self.config.reconnect_delay
            logger.info(f"Long-poll client started for channel {self.config.channel}")

            if self.on_connect:
                await self.on_connect()

            # Polling loop
            await self._poll_loop(self._ssl_context)

        finally:
            await session.close()
            self._session = None
            self._ssl_context = None

    async def _poll_loop(self, ssl_context) -> None:
        """Poll for messages continuously."""
        base_url = self.config.cloud_url.rstrip("/")
        poll_url = f"{base_url}/connect/stream/{self.config.channel}/poll"

        headers = self._get_headers()

        while not self._stop_event.is_set():
            try:
                async with self._session.get(
                    poll_url,
                    headers=headers,
                    params={"timeout": self._poll_timeout, "max_messages": 10},
                    timeout=aiohttp.ClientTimeout(
                        total=self._poll_timeout + 5  # Extra time for network
                    ),
                    ssl=ssl_context,
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        # Update connection ID from server
                        if "connection_id" in data:
                            self.connection_id = data["connection_id"]

                        # Process messages
                        messages = data.get("messages", [])
                        for msg in messages:
                            msg["type"] = "webhook"
                            try:
                                await self.on_message(msg)
                            except Exception as e:
                                logger.error(f"Error processing message: {e}")

                    elif response.status == 204:
                        # No messages, poll again
                        logger.debug("No messages available, polling again")

                    elif response.status == 401:
                        logger.error("Authentication failed")
                        raise Exception("Authentication failed")

                    elif response.status == 404:
                        logger.error("Channel not found")
                        raise Exception("Channel not found")

                    else:
                        logger.warning(f"Unexpected status: {response.status}")
                        # Brief delay before retry
                        await asyncio.sleep(1)

            except asyncio.TimeoutError:
                logger.debug("Poll timeout, retrying")
            except aiohttp.ClientError as e:
                logger.error(f"Connection error: {e}")
                raise
            except Exception as e:
                logger.error(f"Poll error: {e}")
                raise

    async def send_ack(self, message_id: str) -> bool:
        """Send acknowledgment via HTTP POST."""
        if not self._session or self._session.closed:
            return False

        base_url = self.config.cloud_url.rstrip("/")
        ack_url = f"{base_url}/connect/ack"

        try:
            async with self._session.post(
                ack_url,
                params={"message_id": message_id, "status": "ack"},
                headers={
                    "Authorization": f"Bearer {self.config.token}",
                    "X-Connection-ID": self.connection_id or "",
                },
                ssl=self._ssl_context,
            ) as response:
                if response.status == 200:
                    logger.debug(f"Sent ACK for {message_id}")
                    return True
                else:
                    logger.error(f"ACK failed with status {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send ACK: {e}")
            return False

    async def send_nack(self, message_id: str, retry: bool = True) -> bool:
        """Send negative acknowledgment via HTTP POST."""
        if not self._session or self._session.closed:
            return False

        base_url = self.config.cloud_url.rstrip("/")
        ack_url = f"{base_url}/connect/ack"

        try:
            async with self._session.post(
                ack_url,
                params={
                    "message_id": message_id,
                    "status": "nack",
                    "retry": str(retry).lower(),
                },
                headers={
                    "Authorization": f"Bearer {self.config.token}",
                    "X-Connection-ID": self.connection_id or "",
                },
                ssl=self._ssl_context,
            ) as response:
                if response.status == 200:
                    logger.debug(f"Sent NACK for {message_id}, retry={retry}")
                    return True
                else:
                    logger.error(f"NACK failed with status {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send NACK: {e}")
            return False


def create_client(
    config: ConnectorConfig,
    on_message: Callable[[Dict[str, Any]], Awaitable[None]],
    on_connect: Optional[Callable[[], Awaitable[None]]] = None,
    on_disconnect: Optional[Callable[[Optional[Exception]], Awaitable[None]]] = None,
) -> StreamClient:
    """
    Create appropriate stream client based on configuration.

    Args:
        config: Connector configuration
        on_message: Callback for received messages
        on_connect: Optional callback when connected
        on_disconnect: Optional callback when disconnected

    Returns:
        StreamClient instance (WebSocket, SSE, or LongPoll)
    """
    if config.protocol == "websocket":
        return WebSocketClient(config, on_message, on_connect, on_disconnect)
    elif config.protocol == "sse":
        return SSEClient(config, on_message, on_connect, on_disconnect)
    elif config.protocol == "long_poll":
        return LongPollClient(config, on_message, on_connect, on_disconnect)
    else:
        raise ValueError(f"Unknown protocol: {config.protocol}")
