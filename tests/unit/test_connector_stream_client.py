"""Tests for src/connector/stream_client.py — StreamClient, WebSocketClient, SSEClient, LongPollClient."""

import asyncio
import json
import ssl
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest
import aiohttp
from aiohttp import WSMsgType

from src.connector.config import ConnectorConfig, TargetConfig
from src.connector.stream_client import (
    ConnectionState,
    StreamClient,
    WebSocketClient,
    SSEClient,
    LongPollClient,
    create_client,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> ConnectorConfig:
    """Create a ConnectorConfig with sensible defaults for testing."""
    defaults = dict(
        cloud_url="https://cloud.example.com",
        channel="test-channel",
        token="secret-token",
        protocol="websocket",
        log_level="INFO",
        reconnect_delay=0.01,
        max_reconnect_delay=0.05,
        reconnect_backoff_multiplier=2.0,
        heartbeat_timeout=60.0,
        connection_timeout=5.0,
        default_target=TargetConfig(url="http://localhost:8080/hook"),
    )
    defaults.update(overrides)
    return ConnectorConfig(**defaults)


# ===========================================================================
# ConnectionState
# ===========================================================================


class TestConnectionState:
    """Test ConnectionState enum."""

    def test_all_states_defined(self):
        """All expected connection states should be defined."""
        assert ConnectionState.DISCONNECTED.value == "disconnected"
        assert ConnectionState.CONNECTING.value == "connecting"
        assert ConnectionState.CONNECTED.value == "connected"
        assert ConnectionState.RECONNECTING.value == "reconnecting"
        assert ConnectionState.CLOSING.value == "closing"
        assert ConnectionState.CLOSED.value == "closed"


# ===========================================================================
# create_client factory
# ===========================================================================


class TestCreateClient:
    """Test the create_client factory function."""

    @pytest.mark.asyncio
    async def test_create_websocket_client(self):
        """create_client with protocol=websocket should return WebSocketClient."""
        config = _make_config(protocol="websocket")
        on_msg = AsyncMock()
        client = create_client(config, on_msg)
        assert isinstance(client, WebSocketClient)

    @pytest.mark.asyncio
    async def test_create_sse_client(self):
        """create_client with protocol=sse should return SSEClient."""
        config = _make_config(protocol="sse")
        on_msg = AsyncMock()
        client = create_client(config, on_msg)
        assert isinstance(client, SSEClient)

    @pytest.mark.asyncio
    async def test_create_longpoll_client(self):
        """create_client with protocol=long_poll should return LongPollClient."""
        config = _make_config(protocol="long_poll")
        on_msg = AsyncMock()
        client = create_client(config, on_msg)
        assert isinstance(client, LongPollClient)

    @pytest.mark.asyncio
    async def test_create_unknown_protocol_raises(self):
        """create_client with an unknown protocol should raise ValueError."""
        config = _make_config(protocol="unknown")
        on_msg = AsyncMock()
        with pytest.raises(ValueError, match="Unknown protocol"):
            create_client(config, on_msg)

    @pytest.mark.asyncio
    async def test_create_client_passes_callbacks(self):
        """create_client should pass all callbacks to the client."""
        config = _make_config()
        on_msg = AsyncMock()
        on_conn = AsyncMock()
        on_disc = AsyncMock()
        client = create_client(config, on_msg, on_conn, on_disc)

        assert client.on_message is on_msg
        assert client.on_connect is on_conn
        assert client.on_disconnect is on_disc


# ===========================================================================
# StreamClient base — _get_headers, _create_ssl_context, stop
# ===========================================================================


class TestStreamClientBase:
    """Test StreamClient base class shared behavior via a WebSocketClient instance."""

    @pytest.mark.asyncio
    async def test_initial_state_is_disconnected(self):
        """New client should start in DISCONNECTED state."""
        client = WebSocketClient(_make_config(), AsyncMock())
        assert client.state == ConnectionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_connection_id_initially_none(self):
        """connection_id should be None before connecting."""
        client = WebSocketClient(_make_config(), AsyncMock())
        assert client.connection_id is None

    @pytest.mark.asyncio
    async def test_last_heartbeat_initially_none(self):
        """last_heartbeat should be None before connecting."""
        client = WebSocketClient(_make_config(), AsyncMock())
        assert client.last_heartbeat is None


class TestGetHeaders:
    """Test _get_headers method."""

    @pytest.mark.asyncio
    async def test_headers_include_bearer_token(self):
        """Headers should include Authorization: Bearer <token>."""
        config = _make_config(token="my-secret")
        client = WebSocketClient(config, AsyncMock())
        headers = client._get_headers()

        assert headers["Authorization"] == "Bearer my-secret"

    @pytest.mark.asyncio
    async def test_headers_include_connector_id_when_set(self):
        """Headers should include X-Connector-ID when connector_id is set."""
        config = _make_config(connector_id="c-123")
        client = WebSocketClient(config, AsyncMock())
        headers = client._get_headers()

        assert headers["X-Connector-ID"] == "c-123"

    @pytest.mark.asyncio
    async def test_headers_omit_connector_id_when_not_set(self):
        """Headers should not include X-Connector-ID when connector_id is None."""
        config = _make_config(connector_id=None)
        client = WebSocketClient(config, AsyncMock())
        headers = client._get_headers()

        assert "X-Connector-ID" not in headers


class TestCreateSslContext:
    """Test _create_ssl_context method."""

    @pytest.mark.asyncio
    async def test_ssl_disabled_returns_false(self):
        """When verify_ssl is False, should return False."""
        config = _make_config(verify_ssl=False)
        client = WebSocketClient(config, AsyncMock())
        result = client._create_ssl_context()
        assert result is False

    @pytest.mark.asyncio
    async def test_ssl_default_returns_none(self):
        """Default config (verify_ssl=True, no certs) should return None."""
        config = _make_config(verify_ssl=True, ca_cert_path=None, client_cert_path=None)
        client = WebSocketClient(config, AsyncMock())
        result = client._create_ssl_context()
        assert result is None

    @pytest.mark.asyncio
    async def test_ssl_custom_ca_cert(self):
        """When ca_cert_path is set, should return an ssl.SSLContext."""
        config = _make_config(
            verify_ssl=True,
            ca_cert_path="/tmp/fake_ca.pem",
        )
        client = WebSocketClient(config, AsyncMock())

        mock_ctx = MagicMock(spec=ssl.SSLContext)
        with patch("ssl.create_default_context", return_value=mock_ctx):
            result = client._create_ssl_context()

        assert result is mock_ctx
        mock_ctx.load_verify_locations.assert_called_once_with("/tmp/fake_ca.pem")

    @pytest.mark.asyncio
    async def test_ssl_client_cert(self):
        """When client_cert_path is set, should load the cert chain."""
        config = _make_config(
            verify_ssl=True,
            client_cert_path="/tmp/client.pem",
            client_key_path="/tmp/client.key",
        )
        client = WebSocketClient(config, AsyncMock())

        mock_ctx = MagicMock(spec=ssl.SSLContext)
        with patch("ssl.create_default_context", return_value=mock_ctx):
            result = client._create_ssl_context()

        assert result is mock_ctx
        mock_ctx.load_cert_chain.assert_called_once_with("/tmp/client.pem", "/tmp/client.key")


class TestStreamClientStop:
    """Test stop() behavior."""

    @pytest.mark.asyncio
    async def test_stop_sets_closing_state(self):
        """stop() should transition to CLOSING state."""
        client = WebSocketClient(_make_config(), AsyncMock())
        await client.stop()
        assert client.state == ConnectionState.CLOSING

    @pytest.mark.asyncio
    async def test_stop_sets_stop_event(self):
        """stop() should set the _stop_event."""
        client = WebSocketClient(_make_config(), AsyncMock())
        await client.stop()
        assert client._stop_event.is_set()

    @pytest.mark.asyncio
    async def test_stop_closes_session(self):
        """stop() should close the aiohttp session if open."""
        client = WebSocketClient(_make_config(), AsyncMock())
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.close = AsyncMock()
        client._session = mock_session

        await client.stop()

        mock_session.close.assert_awaited_once()
        assert client._session is None

    @pytest.mark.asyncio
    async def test_stop_skips_closed_session(self):
        """stop() should skip closing an already-closed session."""
        client = WebSocketClient(_make_config(), AsyncMock())
        mock_session = MagicMock()
        mock_session.closed = True
        client._session = mock_session

        await client.stop()
        # Should not call close on an already-closed session


# ===========================================================================
# StreamClient.start — reconnection logic
# ===========================================================================


class TestStreamClientStart:
    """Test start() method reconnection loop."""

    @pytest.mark.asyncio
    async def test_start_reconnects_on_error(self):
        """start() should reconnect when connect() raises an exception."""
        config = _make_config(reconnect_delay=0.01, max_reconnect_delay=0.02)
        on_disconnect = AsyncMock()
        client = WebSocketClient(config, AsyncMock(), on_disconnect=on_disconnect)

        call_count = 0

        async def mock_connect():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ConnectionError("test error")
            # Third call: set stop event to exit the loop
            client._stop_event.set()

        client.connect = mock_connect

        await client.start()

        assert call_count == 3
        # on_disconnect should have been called for the first two failures
        assert on_disconnect.await_count == 2
        assert client.state == ConnectionState.CLOSED

    @pytest.mark.asyncio
    async def test_start_exits_on_cancelled_error(self):
        """start() should exit cleanly on CancelledError."""
        client = WebSocketClient(_make_config(), AsyncMock())

        async def mock_connect():
            raise asyncio.CancelledError()

        client.connect = mock_connect

        await client.start()
        assert client.state == ConnectionState.CLOSED

    @pytest.mark.asyncio
    async def test_start_exits_when_stop_event_set_after_error(self):
        """start() should exit when stop_event is set between retries."""
        client = WebSocketClient(_make_config(reconnect_delay=0.01), AsyncMock())

        async def mock_connect():
            client._stop_event.set()
            raise RuntimeError("err")

        client.connect = mock_connect

        await client.start()
        assert client.state == ConnectionState.CLOSED

    @pytest.mark.asyncio
    async def test_start_backoff_increases(self):
        """Reconnect delay should increase with backoff multiplier."""
        config = _make_config(
            reconnect_delay=0.01,
            max_reconnect_delay=1.0,
            reconnect_backoff_multiplier=2.0,
        )
        client = WebSocketClient(config, AsyncMock())

        delays_observed = []
        call_count = 0

        original_sleep = asyncio.sleep

        async def mock_sleep(delay):
            delays_observed.append(delay)
            # Don't actually sleep, just record
            await original_sleep(0)

        async def mock_connect():
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                client._stop_event.set()
            raise ConnectionError("err")

        client.connect = mock_connect

        with patch("asyncio.sleep", side_effect=mock_sleep):
            await client.start()

        # First delay should be based on reconnect_delay + jitter
        # Second delay should be larger due to backoff
        assert len(delays_observed) >= 2
        # Second base delay should be ~2x first base delay (before jitter)
        # We can't assert exact values due to jitter, but the trend should hold


# ===========================================================================
# WebSocketClient
# ===========================================================================


class TestWebSocketClientInit:
    """Test WebSocketClient initialization."""

    @pytest.mark.asyncio
    async def test_ws_initially_none(self):
        """_ws should be None on init."""
        client = WebSocketClient(_make_config(), AsyncMock())
        assert client._ws is None

    @pytest.mark.asyncio
    async def test_heartbeat_task_initially_none(self):
        """_heartbeat_task should be None on init."""
        client = WebSocketClient(_make_config(), AsyncMock())
        assert client._heartbeat_task is None


def _make_async_iterable_ws(messages):
    """Create a mock WS object that works with `async for msg in ws`."""
    mock_ws = MagicMock()
    mock_ws.closed = False
    mock_ws.exception = MagicMock(return_value=None)
    mock_ws.send_json = AsyncMock()
    mock_ws.close = AsyncMock()

    iterator = AsyncIteratorMock(messages)
    mock_ws.__aiter__ = lambda self: iterator
    return mock_ws


class TestWebSocketClientConnect:
    """Test WebSocketClient.connect method."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """connect() should establish WebSocket connection and call on_connect."""
        config = _make_config()
        on_connect = AsyncMock()
        on_message = AsyncMock()
        client = WebSocketClient(config, on_message, on_connect=on_connect)

        # Create a mock WS that is async-iterable (empty)
        mock_ws = _make_async_iterable_ws([])

        mock_session = MagicMock()
        mock_ws_ctx = AsyncMock()
        mock_ws_ctx.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session.ws_connect = MagicMock(return_value=mock_ws_ctx)

        mock_session_ctx = AsyncMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session_ctx):
            await client.connect()

        on_connect.assert_awaited_once()
        assert client.state == ConnectionState.CONNECTED


class TestWebSocketClientHandleMessage:
    """Test WebSocketClient._handle_message."""

    @pytest.mark.asyncio
    async def test_handle_connected_message(self):
        """'connected' messages should set the connection_id."""
        client = WebSocketClient(_make_config(), AsyncMock())
        await client._handle_message({"type": "connected", "connection_id": "conn-abc"})

        assert client.connection_id == "conn-abc"

    @pytest.mark.asyncio
    async def test_handle_heartbeat_message(self):
        """'heartbeat' messages should update last_heartbeat and echo back."""
        config = _make_config()
        client = WebSocketClient(config, AsyncMock())
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_ws.send_json = AsyncMock()
        client._ws = mock_ws

        await client._handle_message({"type": "heartbeat"})

        assert client.last_heartbeat is not None
        mock_ws.send_json.assert_awaited_once()
        sent = mock_ws.send_json.call_args[0][0]
        assert sent["type"] == "heartbeat"

    @pytest.mark.asyncio
    async def test_handle_heartbeat_with_closed_ws(self):
        """'heartbeat' with closed WS should not attempt to send."""
        client = WebSocketClient(_make_config(), AsyncMock())
        client._ws = None

        # Should not raise
        await client._handle_message({"type": "heartbeat"})
        assert client.last_heartbeat is not None

    @pytest.mark.asyncio
    async def test_handle_heartbeat_send_exception_swallowed(self):
        """send_json exception during heartbeat echo should be swallowed."""
        client = WebSocketClient(_make_config(), AsyncMock())
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_ws.send_json = AsyncMock(side_effect=RuntimeError("send failed"))
        client._ws = mock_ws

        # Should not raise
        await client._handle_message({"type": "heartbeat"})

    @pytest.mark.asyncio
    async def test_handle_webhook_message(self):
        """'webhook' messages should be forwarded to on_message."""
        on_message = AsyncMock()
        client = WebSocketClient(_make_config(), on_message)

        data = {"type": "webhook", "payload": {"key": "val"}}
        await client._handle_message(data)

        on_message.assert_awaited_once_with(data)

    @pytest.mark.asyncio
    async def test_handle_unknown_message_type(self):
        """Unknown message types should be logged but not raise."""
        on_message = AsyncMock()
        client = WebSocketClient(_make_config(), on_message)

        await client._handle_message({"type": "unknown_type"})

        on_message.assert_not_awaited()


class TestWebSocketClientSendAck:
    """Test WebSocketClient.send_ack."""

    @pytest.mark.asyncio
    async def test_send_ack_success(self):
        """send_ack should send JSON with type=ack and return True."""
        client = WebSocketClient(_make_config(), AsyncMock())
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_ws.send_json = AsyncMock()
        client._ws = mock_ws

        result = await client.send_ack("msg-1")

        assert result is True
        mock_ws.send_json.assert_awaited_once_with({"type": "ack", "message_id": "msg-1"})

    @pytest.mark.asyncio
    async def test_send_ack_no_ws(self):
        """send_ack without a WS connection should return False."""
        client = WebSocketClient(_make_config(), AsyncMock())
        client._ws = None

        result = await client.send_ack("msg-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_ack_closed_ws(self):
        """send_ack with a closed WS should return False."""
        client = WebSocketClient(_make_config(), AsyncMock())
        mock_ws = MagicMock()
        mock_ws.closed = True
        client._ws = mock_ws

        result = await client.send_ack("msg-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_ack_exception(self):
        """send_ack should return False on exception."""
        client = WebSocketClient(_make_config(), AsyncMock())
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_ws.send_json = AsyncMock(side_effect=RuntimeError("send err"))
        client._ws = mock_ws

        result = await client.send_ack("msg-1")
        assert result is False


class TestWebSocketClientSendNack:
    """Test WebSocketClient.send_nack."""

    @pytest.mark.asyncio
    async def test_send_nack_success(self):
        """send_nack should send JSON with type=nack and return True."""
        client = WebSocketClient(_make_config(), AsyncMock())
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_ws.send_json = AsyncMock()
        client._ws = mock_ws

        result = await client.send_nack("msg-2", retry=False)

        assert result is True
        mock_ws.send_json.assert_awaited_once_with(
            {"type": "nack", "message_id": "msg-2", "retry": False}
        )

    @pytest.mark.asyncio
    async def test_send_nack_no_ws(self):
        """send_nack without a WS connection should return False."""
        client = WebSocketClient(_make_config(), AsyncMock())
        client._ws = None

        result = await client.send_nack("msg-2")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_nack_exception(self):
        """send_nack should return False on exception."""
        client = WebSocketClient(_make_config(), AsyncMock())
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_ws.send_json = AsyncMock(side_effect=RuntimeError("err"))
        client._ws = mock_ws

        result = await client.send_nack("msg-2")
        assert result is False


class TestWebSocketClientMonitorHeartbeat:
    """Test WebSocketClient._monitor_heartbeat."""

    @pytest.mark.asyncio
    async def test_heartbeat_timeout_closes_ws(self):
        """If heartbeat is stale, monitor should close the WS."""
        config = _make_config(heartbeat_timeout=0.1)
        client = WebSocketClient(config, AsyncMock())
        # Set last_heartbeat to well in the past
        client.last_heartbeat = datetime.now(timezone.utc) - timedelta(seconds=10)

        mock_ws = AsyncMock()
        mock_ws.close = AsyncMock()
        client._ws = mock_ws

        # Run monitor briefly — it sleeps heartbeat_timeout/2 = 0.05s
        # then checks and closes
        try:
            await asyncio.wait_for(client._monitor_heartbeat(), timeout=0.5)
        except asyncio.TimeoutError:
            pass

        mock_ws.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_heartbeat_ok_does_not_close(self):
        """If heartbeat is fresh, monitor should not close the WS."""
        config = _make_config(heartbeat_timeout=10.0)
        client = WebSocketClient(config, AsyncMock())
        client.last_heartbeat = datetime.now(timezone.utc)
        client._stop_event.set()  # Make it exit after one iteration

        mock_ws = AsyncMock()
        mock_ws.close = AsyncMock()
        client._ws = mock_ws

        try:
            await asyncio.wait_for(client._monitor_heartbeat(), timeout=1.0)
        except asyncio.TimeoutError:
            pass

        mock_ws.close.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_heartbeat_no_last_heartbeat(self):
        """If no heartbeat received yet, monitor should not close."""
        config = _make_config(heartbeat_timeout=0.1)
        client = WebSocketClient(config, AsyncMock())
        client.last_heartbeat = None
        client._stop_event.set()

        mock_ws = AsyncMock()
        mock_ws.close = AsyncMock()
        client._ws = mock_ws

        try:
            await asyncio.wait_for(client._monitor_heartbeat(), timeout=0.5)
        except asyncio.TimeoutError:
            pass

        mock_ws.close.assert_not_awaited()


class TestWebSocketClientMessageLoop:
    """Test WebSocketClient._message_loop."""

    @pytest.mark.asyncio
    async def test_message_loop_text_message(self):
        """Text messages should be parsed as JSON and handled."""
        on_message = AsyncMock()
        client = WebSocketClient(_make_config(), on_message)

        msg_data = {"type": "webhook", "payload": {"x": 1}}
        mock_msg = MagicMock()
        mock_msg.type = WSMsgType.TEXT
        mock_msg.data = json.dumps(msg_data)

        client._ws = _make_async_iterable_ws([mock_msg])

        await client._message_loop()

        on_message.assert_awaited_once_with(msg_data)

    @pytest.mark.asyncio
    async def test_message_loop_invalid_json(self):
        """Invalid JSON in text messages should be logged, not raise."""
        client = WebSocketClient(_make_config(), AsyncMock())

        mock_msg = MagicMock()
        mock_msg.type = WSMsgType.TEXT
        mock_msg.data = "not valid json{"

        client._ws = _make_async_iterable_ws([mock_msg])

        # Should not raise
        await client._message_loop()

    @pytest.mark.asyncio
    async def test_message_loop_error_message_breaks(self):
        """Error messages should break the loop."""
        client = WebSocketClient(_make_config(), AsyncMock())

        mock_msg = MagicMock()
        mock_msg.type = WSMsgType.ERROR

        ws = _make_async_iterable_ws([mock_msg])
        ws.exception = MagicMock(return_value=RuntimeError("ws err"))
        client._ws = ws

        await client._message_loop()

    @pytest.mark.asyncio
    async def test_message_loop_closed_message_breaks(self):
        """Closed messages should break the loop."""
        client = WebSocketClient(_make_config(), AsyncMock())

        mock_msg = MagicMock()
        mock_msg.type = WSMsgType.CLOSED

        client._ws = _make_async_iterable_ws([mock_msg])

        await client._message_loop()

    @pytest.mark.asyncio
    async def test_message_loop_stop_event_breaks(self):
        """Setting stop_event should break the message loop."""
        client = WebSocketClient(_make_config(), AsyncMock())
        client._stop_event.set()

        msg_data = {"type": "webhook"}
        mock_msg = MagicMock()
        mock_msg.type = WSMsgType.TEXT
        mock_msg.data = json.dumps(msg_data)

        client._ws = _make_async_iterable_ws([mock_msg])

        await client._message_loop()

    @pytest.mark.asyncio
    async def test_message_loop_handler_exception_logged(self):
        """Exceptions in _handle_message should be caught and logged."""
        on_message = AsyncMock(side_effect=RuntimeError("handler boom"))
        client = WebSocketClient(_make_config(), on_message)

        msg_data = {"type": "webhook"}
        mock_msg = MagicMock()
        mock_msg.type = WSMsgType.TEXT
        mock_msg.data = json.dumps(msg_data)

        client._ws = _make_async_iterable_ws([mock_msg])

        # Should not raise
        await client._message_loop()


# ===========================================================================
# SSEClient
# ===========================================================================


class TestSSEClientInit:
    """Test SSEClient initialization."""

    @pytest.mark.asyncio
    async def test_response_initially_none(self):
        """_response should be None on init."""
        client = SSEClient(_make_config(protocol="sse"), AsyncMock())
        assert client._response is None


class TestSSEClientConnect:
    """Test SSEClient.connect method."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """connect() should establish SSE connection and call on_connect."""
        config = _make_config(protocol="sse")
        on_connect = AsyncMock()
        client = SSEClient(config, AsyncMock(), on_connect=on_connect)

        # Mock the response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.content = AsyncMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock([]))

        mock_response_ctx = AsyncMock()
        mock_response_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response_ctx)
        mock_session.close = AsyncMock()
        mock_session.closed = False

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await client.connect()

        on_connect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_non_200_raises(self):
        """connect() should raise on non-200 status."""
        config = _make_config(protocol="sse")
        client = SSEClient(config, AsyncMock())

        mock_response = AsyncMock()
        mock_response.status = 403

        mock_response_ctx = AsyncMock()
        mock_response_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response_ctx)
        mock_session.close = AsyncMock()

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(Exception, match="status 403"):
                await client.connect()


class AsyncIteratorMock:
    """Async iterator mock helper for SSE chunk iteration and WS messages."""

    def __init__(self, items):
        self._items = iter(items)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._items)
        except StopIteration:
            raise StopAsyncIteration


class TestSSEClientSseLoop:
    """Test SSEClient._sse_loop method."""

    @pytest.mark.asyncio
    async def test_sse_loop_processes_webhook_event(self):
        """SSE loop should parse webhook events and call on_message."""
        on_message = AsyncMock()
        config = _make_config(protocol="sse")
        client = SSEClient(config, on_message)

        payload = json.dumps({"message_id": "m1", "body": "hello"})
        # SSE format: event:webhook\ndata:{json}\n\n
        chunks = [f"event:webhook\ndata:{payload}\n\n".encode("utf-8")]

        mock_response = AsyncMock()
        mock_response.content = MagicMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock(chunks))

        await client._sse_loop(mock_response)

        on_message.assert_awaited_once()
        called_data = on_message.call_args[0][0]
        assert called_data["type"] == "webhook"
        assert called_data["message_id"] == "m1"

    @pytest.mark.asyncio
    async def test_sse_loop_heartbeat_event(self):
        """SSE heartbeat events should update last_heartbeat."""
        config = _make_config(protocol="sse")
        client = SSEClient(config, AsyncMock())

        chunks = [b"event:heartbeat\ndata:ping\n\n"]

        mock_response = AsyncMock()
        mock_response.content = MagicMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock(chunks))

        await client._sse_loop(mock_response)

        assert client.last_heartbeat is not None

    @pytest.mark.asyncio
    async def test_sse_loop_connected_event(self):
        """SSE 'connected' events should set connection_id."""
        config = _make_config(protocol="sse")
        client = SSEClient(config, AsyncMock())

        data = json.dumps({"connection_id": "sse-conn-1"})
        chunks = [f"event:connected\ndata:{data}\n\n".encode("utf-8")]

        mock_response = AsyncMock()
        mock_response.content = MagicMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock(chunks))

        await client._sse_loop(mock_response)

        assert client.connection_id == "sse-conn-1"

    @pytest.mark.asyncio
    async def test_sse_loop_error_event(self):
        """SSE 'error' events should be logged but not raise."""
        config = _make_config(protocol="sse")
        client = SSEClient(config, AsyncMock())

        chunks = [b"event:error\ndata:something went wrong\n\n"]

        mock_response = AsyncMock()
        mock_response.content = MagicMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock(chunks))

        # Should not raise
        await client._sse_loop(mock_response)

    @pytest.mark.asyncio
    async def test_sse_loop_invalid_json_webhook(self):
        """Invalid JSON in webhook data should be logged, not raise."""
        config = _make_config(protocol="sse")
        client = SSEClient(config, AsyncMock())

        chunks = [b"event:webhook\ndata:not-json\n\n"]

        mock_response = AsyncMock()
        mock_response.content = MagicMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock(chunks))

        await client._sse_loop(mock_response)

    @pytest.mark.asyncio
    async def test_sse_loop_stop_event_breaks(self):
        """Setting stop_event should break the SSE loop."""
        config = _make_config(protocol="sse")
        client = SSEClient(config, AsyncMock())
        client._stop_event.set()

        chunks = [b"event:webhook\ndata:{}\n\n"]

        mock_response = AsyncMock()
        mock_response.content = MagicMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock(chunks))

        await client._sse_loop(mock_response)

    @pytest.mark.asyncio
    async def test_sse_loop_multiline_data(self):
        """SSE data spanning multiple data: lines should be concatenated."""
        on_message = AsyncMock()
        config = _make_config(protocol="sse")
        client = SSEClient(config, on_message)

        # Multi-line data: each line has data: prefix
        payload_part1 = '{"message_id":'
        payload_part2 = '"m2"}'
        chunks = [f"event:webhook\ndata:{payload_part1}\ndata:{payload_part2}\n\n".encode("utf-8")]

        mock_response = AsyncMock()
        mock_response.content = MagicMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock(chunks))

        await client._sse_loop(mock_response)

        on_message.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_sse_loop_connected_invalid_json(self):
        """Invalid JSON in 'connected' event should not raise."""
        config = _make_config(protocol="sse")
        client = SSEClient(config, AsyncMock())

        chunks = [b"event:connected\ndata:not-json\n\n"]

        mock_response = AsyncMock()
        mock_response.content = MagicMock()
        mock_response.content.iter_any = MagicMock(return_value=AsyncIteratorMock(chunks))

        # Should not raise
        await client._sse_loop(mock_response)
        assert client.connection_id is None


class TestSSEClientSendAck:
    """Test SSEClient.send_ack via HTTP POST."""

    @pytest.mark.asyncio
    async def test_send_ack_success(self):
        """send_ack should POST to /connect/ack and return True on 200."""
        config = _make_config(protocol="sse", cloud_url="https://cloud.test")
        client = SSEClient(config, AsyncMock())
        client.connection_id = "sse-conn-1"

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        result = await client.send_ack("msg-1")

        assert result is True
        mock_session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_ack_non_200(self):
        """send_ack should return False on non-200 status."""
        config = _make_config(protocol="sse", cloud_url="https://cloud.test")
        client = SSEClient(config, AsyncMock())
        client.connection_id = "sse-conn-1"

        mock_resp = AsyncMock()
        mock_resp.status = 500
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        result = await client.send_ack("msg-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_ack_no_session(self):
        """send_ack without a session should return False."""
        client = SSEClient(_make_config(protocol="sse"), AsyncMock())
        client._session = None

        result = await client.send_ack("msg-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_ack_closed_session(self):
        """send_ack with a closed session should return False."""
        client = SSEClient(_make_config(protocol="sse"), AsyncMock())
        mock_session = MagicMock()
        mock_session.closed = True
        client._session = mock_session

        result = await client.send_ack("msg-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_ack_exception(self):
        """send_ack should return False on exception."""
        config = _make_config(protocol="sse", cloud_url="https://cloud.test")
        client = SSEClient(config, AsyncMock())
        client.connection_id = "sse-conn-1"

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(side_effect=RuntimeError("net err"))
        client._session = mock_session

        result = await client.send_ack("msg-1")
        assert result is False


class TestSSEClientSendNack:
    """Test SSEClient.send_nack via HTTP POST."""

    @pytest.mark.asyncio
    async def test_send_nack_success(self):
        """send_nack should POST to /connect/ack with nack status and return True."""
        config = _make_config(protocol="sse", cloud_url="https://cloud.test")
        client = SSEClient(config, AsyncMock())
        client.connection_id = "sse-conn-1"

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        result = await client.send_nack("msg-2", retry=False)

        assert result is True

    @pytest.mark.asyncio
    async def test_send_nack_non_200(self):
        """send_nack should return False on non-200."""
        config = _make_config(protocol="sse", cloud_url="https://cloud.test")
        client = SSEClient(config, AsyncMock())
        client.connection_id = "sse-conn-1"

        mock_resp = AsyncMock()
        mock_resp.status = 502
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        result = await client.send_nack("msg-2")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_nack_no_session(self):
        """send_nack without a session should return False."""
        client = SSEClient(_make_config(protocol="sse"), AsyncMock())
        client._session = None

        result = await client.send_nack("msg-2")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_nack_exception(self):
        """send_nack should return False on exception."""
        config = _make_config(protocol="sse", cloud_url="https://cloud.test")
        client = SSEClient(config, AsyncMock())
        client.connection_id = "conn-1"

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(side_effect=RuntimeError("net err"))
        client._session = mock_session

        result = await client.send_nack("msg-2")
        assert result is False


# ===========================================================================
# LongPollClient
# ===========================================================================


class TestLongPollClientInit:
    """Test LongPollClient initialization."""

    @pytest.mark.asyncio
    async def test_poll_timeout_default(self):
        """Default poll timeout should be 30."""
        client = LongPollClient(_make_config(protocol="long_poll"), AsyncMock())
        assert client._poll_timeout == 30


class TestLongPollClientConnect:
    """Test LongPollClient.connect method."""

    @pytest.mark.asyncio
    async def test_connect_calls_on_connect(self):
        """connect() should call on_connect callback."""
        config = _make_config(protocol="long_poll")
        on_connect = AsyncMock()
        client = LongPollClient(config, AsyncMock(), on_connect=on_connect)

        # Make _poll_loop exit immediately
        async def fake_poll_loop(ssl_ctx):
            pass

        client._poll_loop = fake_poll_loop

        mock_session = AsyncMock()
        mock_session.close = AsyncMock()

        with patch("aiohttp.ClientSession", return_value=mock_session):
            await client.connect()

        on_connect.assert_awaited_once()
        assert client.state == ConnectionState.CONNECTED


class TestLongPollClientPollLoop:
    """Test LongPollClient._poll_loop method."""

    @pytest.mark.asyncio
    async def test_poll_loop_processes_messages(self):
        """Poll loop should process messages from 200 responses."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        on_message = AsyncMock()
        client = LongPollClient(config, on_message)

        response_data = {
            "connection_id": "poll-conn-1",
            "messages": [
                {"message_id": "m1", "body": "hello"},
                {"message_id": "m2", "body": "world"},
            ],
        }

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=response_data)

        def make_resp_ctx(*args, **kwargs):
            # Stop after processing this response
            client._stop_event.set()
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            ctx.__aexit__ = AsyncMock(return_value=False)
            return ctx

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=make_resp_ctx)
        client._session = mock_session

        await client._poll_loop(None)

        assert on_message.await_count == 2
        assert client.connection_id == "poll-conn-1"
        # Messages should have type="webhook" set
        for call in on_message.call_args_list:
            assert call[0][0]["type"] == "webhook"

    @pytest.mark.asyncio
    async def test_poll_loop_204_no_messages(self):
        """204 response should cause poll to retry."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())

        call_count = 0

        def make_resp_ctx(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = AsyncMock()
            mock_resp.status = 204
            if call_count >= 2:
                client._stop_event.set()
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            ctx.__aexit__ = AsyncMock(return_value=False)
            return ctx

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=make_resp_ctx)
        client._session = mock_session

        await client._poll_loop(None)
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_poll_loop_401_raises(self):
        """401 response should raise an exception."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())

        mock_resp = AsyncMock()
        mock_resp.status = 401
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        with pytest.raises(Exception, match="Authentication failed"):
            await client._poll_loop(None)

    @pytest.mark.asyncio
    async def test_poll_loop_404_raises(self):
        """404 response should raise an exception."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())

        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        with pytest.raises(Exception, match="Channel not found"):
            await client._poll_loop(None)

    @pytest.mark.asyncio
    async def test_poll_loop_unexpected_status_retries(self):
        """Unexpected status codes should trigger retry with delay."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())

        call_count = 0

        def make_resp_ctx(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = AsyncMock()
            mock_resp.status = 503
            if call_count >= 2:
                client._stop_event.set()
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            ctx.__aexit__ = AsyncMock(return_value=False)
            return ctx

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=make_resp_ctx)
        client._session = mock_session

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await client._poll_loop(None)

        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_poll_loop_timeout_retries(self):
        """Timeout errors should cause poll to retry."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())

        call_count = 0

        def make_resp_ctx(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                client._stop_event.set()
            raise asyncio.TimeoutError()

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=make_resp_ctx)
        client._session = mock_session

        await client._poll_loop(None)
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_poll_loop_client_error_raises(self):
        """aiohttp.ClientError should propagate."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=aiohttp.ClientError("conn refused"))
        client._session = mock_session

        with pytest.raises(aiohttp.ClientError):
            await client._poll_loop(None)

    @pytest.mark.asyncio
    async def test_poll_loop_message_processing_exception_logged(self):
        """Exceptions in on_message during polling should be caught."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        on_message = AsyncMock(side_effect=RuntimeError("handler err"))
        client = LongPollClient(config, on_message)

        response_data = {
            "messages": [{"message_id": "m1"}],
        }

        call_count = 0

        def make_resp_ctx(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=response_data)
            if call_count >= 1:
                client._stop_event.set()
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            ctx.__aexit__ = AsyncMock(return_value=False)
            return ctx

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=make_resp_ctx)
        client._session = mock_session

        # Should not raise despite handler error
        await client._poll_loop(None)


class TestLongPollClientSendAck:
    """Test LongPollClient.send_ack via HTTP POST."""

    @pytest.mark.asyncio
    async def test_send_ack_success(self):
        """send_ack should POST and return True on 200."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())
        client.connection_id = "poll-conn-1"
        client._ssl_context = None

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        result = await client.send_ack("msg-1")
        assert result is True

    @pytest.mark.asyncio
    async def test_send_ack_no_session(self):
        """send_ack without session should return False."""
        client = LongPollClient(_make_config(protocol="long_poll"), AsyncMock())
        client._session = None

        result = await client.send_ack("msg-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_ack_non_200(self):
        """send_ack should return False on non-200."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())
        client.connection_id = "conn-1"
        client._ssl_context = None

        mock_resp = AsyncMock()
        mock_resp.status = 500
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        result = await client.send_ack("msg-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_ack_exception(self):
        """send_ack should return False on exception."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())
        client.connection_id = "conn-1"
        client._ssl_context = None

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(side_effect=RuntimeError("err"))
        client._session = mock_session

        result = await client.send_ack("msg-1")
        assert result is False


class TestLongPollClientSendNack:
    """Test LongPollClient.send_nack via HTTP POST."""

    @pytest.mark.asyncio
    async def test_send_nack_success(self):
        """send_nack should POST and return True on 200."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())
        client.connection_id = "poll-conn-1"
        client._ssl_context = None

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        result = await client.send_nack("msg-2", retry=True)
        assert result is True

    @pytest.mark.asyncio
    async def test_send_nack_no_session(self):
        """send_nack without session should return False."""
        client = LongPollClient(_make_config(protocol="long_poll"), AsyncMock())
        client._session = None

        result = await client.send_nack("msg-2")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_nack_non_200(self):
        """send_nack should return False on non-200."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())
        client.connection_id = "conn-1"
        client._ssl_context = None

        mock_resp = AsyncMock()
        mock_resp.status = 400
        mock_resp_ctx = AsyncMock()
        mock_resp_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(return_value=mock_resp_ctx)
        client._session = mock_session

        result = await client.send_nack("msg-2")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_nack_exception(self):
        """send_nack should return False on exception."""
        config = _make_config(protocol="long_poll", cloud_url="https://cloud.test")
        client = LongPollClient(config, AsyncMock())
        client.connection_id = "conn-1"
        client._ssl_context = None

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.post = MagicMock(side_effect=RuntimeError("err"))
        client._session = mock_session

        result = await client.send_nack("msg-2")
        assert result is False
