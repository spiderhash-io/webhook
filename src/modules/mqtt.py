import json
import re
import ssl
from typing import Any, Dict, Optional
from aiomqtt import Client as MQTTClient, ProtocolVersion
from src.modules.base import BaseModule


class MQTTModule(BaseModule):
    """Module for publishing webhook payloads to MQTT brokers."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.client: Optional[MQTTClient] = None
        # Validate topic name during initialization to fail early
        raw_topic = self.config.get('topic')
        if raw_topic is None:
            raw_topic = self.module_config.get('topic')
        if raw_topic is not None:
            self._validated_topic = self._validate_topic_name(raw_topic)
        else:
            self._validated_topic = None
    
    def _validate_topic_name(self, topic_name: str) -> str:
        """
        Validate and sanitize MQTT topic name to prevent injection.
        
        MQTT topics can contain:
        - Alphanumeric characters
        - Forward slash (/) for hierarchy
        - Plus sign (+) for single-level wildcard
        - Hash (#) for multi-level wildcard (only at end)
        
        However, for security, we restrict wildcards in published topics.
        
        Args:
            topic_name: The topic name from configuration
            
        Returns:
            Validated and sanitized topic name
            
        Raises:
            ValueError: If topic name is invalid or contains dangerous characters
        """
        if not topic_name or not isinstance(topic_name, str):
            raise ValueError("Topic name must be a non-empty string")
        
        # Remove whitespace
        topic_name = topic_name.strip()
        
        if not topic_name:
            raise ValueError("Topic name cannot be empty")
        
        # Maximum length to prevent DoS (MQTT spec allows up to 65535 bytes, but we enforce reasonable limit)
        MAX_TOPIC_LENGTH = 32768  # Half of MQTT spec limit for safety
        if len(topic_name.encode('utf-8')) > MAX_TOPIC_LENGTH:
            raise ValueError(f"Topic name too long: {len(topic_name.encode('utf-8'))} bytes (max: {MAX_TOPIC_LENGTH})")
        
        # Minimum length
        if len(topic_name) < 1:
            raise ValueError("Topic name too short (minimum 1 character)")
        
        # Block null bytes
        if '\x00' in topic_name:
            raise ValueError("Topic name cannot contain null bytes (forbidden control character)")
        
        # Block control characters FIRST (before regex check)
        if any(char in topic_name for char in ['\r', '\n', '\t']):
            raise ValueError("Topic name contains forbidden control characters")
        
        # Block dangerous patterns that could be used for injection (check before regex)
        # Check double hyphen and double dot first (common patterns)
        if '--' in topic_name:
            raise ValueError("Topic name contains dangerous pattern: '--' (not allowed)")
        if '..' in topic_name:
            raise ValueError("Topic name contains dangerous pattern: '..' (not allowed)")
        
        dangerous_patterns = [';', '/*', '*/', '(', ')', '[', ']', '{', '}', '|', '&', '$', '`', '\\', ':', '@', '%']
        for pattern in dangerous_patterns:
            if pattern in topic_name:
                raise ValueError(f"Topic name contains dangerous pattern: '{pattern}' (not allowed)")
        
        # Block wildcards (security: don't allow publishing to wildcard topics)
        if '+' in topic_name or '#' in topic_name:
            raise ValueError("Topic name cannot contain wildcards (+ or #) for published topics")
        
        # MQTT topic validation: allow alphanumeric, /, -, _, .
        # But restrict wildcards for published topics (security)
        # Allow: alphanumeric, forward slash, hyphen, underscore, dot
        # Block: + and # (wildcards should not be used in published topics)
        if not re.match(r'^[a-zA-Z0-9_\-\./]+$', topic_name):
            raise ValueError(
                f"Invalid topic name format: '{topic_name}'. "
                f"Only alphanumeric characters, underscores, hyphens, dots, and forward slashes are allowed. "
                f"Wildcards (+ and #) are not allowed in published topics."
            )
        
        # Block consecutive slashes (except at start for absolute topics)
        if '//' in topic_name:
            raise ValueError("Topic name cannot contain consecutive slashes")
        
        # Block topics that are only slashes
        if topic_name.strip('/') == '':
            raise ValueError("Topic name cannot consist only of slashes")
        
        # Block topics starting with $ (reserved for system topics in some brokers)
        if topic_name.startswith('$'):
            raise ValueError("Topic name cannot start with '$' (reserved for system topics)")
        
        return topic_name
    
    def _get_mqtt_version(self) -> ProtocolVersion:
        """Get MQTT protocol version from config."""
        version_str = self.connection_details.get('mqtt_version', '3.1.1')
        if version_str == '5.0' or version_str == '5':
            return ProtocolVersion.V5
        else:
            return ProtocolVersion.V31
    
    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for TLS connections if configured."""
        if not self.connection_details.get('tls', False):
            return None
        
        ssl_context = ssl.create_default_context()
        
        # Allow self-signed certificates if configured
        if self.connection_details.get('tls_insecure', False):
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # Load client certificate if provided
        cert_file = self.connection_details.get('tls_cert_file')
        key_file = self.connection_details.get('tls_key_file')
        if cert_file and key_file:
            ssl_context.load_cert_chain(cert_file, key_file)
        
        # Load CA certificate if provided
        ca_cert_file = self.connection_details.get('tls_ca_cert_file')
        if ca_cert_file:
            ssl_context.load_verify_locations(ca_cert_file)
        
        return ssl_context
    
    async def setup(self) -> None:
        """Initialize MQTT client connection."""
        if self.client:
            return  # Already connected
        
        # Get connection parameters
        host = self.connection_details.get('host', 'localhost')
        port = self.connection_details.get('port', 1883)
        username = self.connection_details.get('username')
        password = self.connection_details.get('password')
        client_id = self.connection_details.get('client_id', 'webhook-module')
        keepalive = self.connection_details.get('keepalive', 60)
        mqtt_version = self._get_mqtt_version()
        ssl_context = self._get_ssl_context()
        
        # Create client (will be used as context manager in process method)
        # Note: aiomqtt uses 'identifier' instead of 'client_id' and 'protocol' instead of 'version'
        self.client = MQTTClient(
            hostname=host,
            port=port,
            username=username,
            password=password,
            identifier=client_id,
            keepalive=keepalive,
            protocol=mqtt_version,
            tls_context=ssl_context
        )
        
        # Enter context manager
        await self.client.__aenter__()
    
    async def teardown(self) -> None:
        """Close MQTT client connection."""
        if self.client:
            try:
                await self.client.__aexit__(None, None, None)
            except Exception as e:
                print(f"Error closing MQTT client: {e}")
            finally:
                self.client = None
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Publish payload to MQTT topic."""
        topic = self._validated_topic
        
        if not topic:
            raise ValueError("MQTT topic is required and must be validated")
        
        # Get or create client
        if not self.client:
            await self.setup()
        
        try:
            # Get QoS level (default: 1 for reliability)
            qos = self.module_config.get('qos', 1)
            if qos not in [0, 1, 2]:
                raise ValueError(f"Invalid QoS level: {qos}. Must be 0, 1, or 2")
            
            # Get retained flag
            retained = self.module_config.get('retained', False)
            
            # Prepare message payload
            message_format = self.module_config.get('format', 'json')
            if message_format == 'json':
                if isinstance(payload, (dict, list)):
                    message = json.dumps(payload).encode('utf-8')
                else:
                    message = str(payload).encode('utf-8')
            elif message_format == 'raw':
                if isinstance(payload, bytes):
                    message = payload
                elif isinstance(payload, str):
                    message = payload.encode('utf-8')
                else:
                    message = str(payload).encode('utf-8')
            else:
                # Default to JSON
                message = json.dumps(payload).encode('utf-8')
            
            # Handle Shelly Gen2 format (single JSON topic)
            if self.module_config.get('shelly_gen2_format', False):
                # Shelly Gen2 uses a single topic with full JSON payload
                shelly_topic = topic
                device_id = self.module_config.get('device_id', 'webhook')
                # SECURITY: Validate device_id to prevent injection in JSON payload
                # Device ID is used in JSON, not in topic, but validate for safety
                if not isinstance(device_id, str):
                    device_id = str(device_id)  # Convert to string for JSON serialization
                shelly_payload = {
                    "id": device_id,
                    "source": "webhook",
                    "params": payload if isinstance(payload, dict) else {"data": payload}
                }
                message = json.dumps(shelly_payload).encode('utf-8')
            
            # Handle Sonoff/Tasmota format
            elif self.module_config.get('tasmota_format', False):
                tasmota_type = self.module_config.get('tasmota_type', 'cmnd')  # cmnd, stat, or tele
                device_name = self.module_config.get('device_name', 'webhook')
                
                # SECURITY: Validate device_name to prevent topic injection
                if not isinstance(device_name, str):
                    raise ValueError("Tasmota device_name must be a string")
                device_name = device_name.strip()
                if not device_name:
                    raise ValueError("Tasmota device_name cannot be empty")
                # Validate device_name format (same as topic validation)
                if not re.match(r'^[a-zA-Z0-9_\-\./]+$', device_name):
                    raise ValueError("Invalid Tasmota device_name format")
                # Reject dangerous patterns
                if '..' in device_name or '--' in device_name or '+' in device_name or '#' in device_name:
                    raise ValueError("Tasmota device_name contains dangerous pattern")
                
                if tasmota_type == 'cmnd':
                    # Command format: cmnd/device_name/command
                    # For webhooks, we'll use a generic command or the topic
                    command = self.module_config.get('command', 'webhook')
                    # SECURITY: Validate command to prevent topic injection
                    if not isinstance(command, str):
                        raise ValueError("Tasmota command must be a string")
                    command = command.strip()
                    if not command:
                        raise ValueError("Tasmota command cannot be empty")
                    # Validate command format (same as topic validation)
                    if not re.match(r'^[a-zA-Z0-9_\-\./]+$', command):
                        raise ValueError("Invalid Tasmota command format")
                    # Reject dangerous patterns
                    if '..' in command or '--' in command or '+' in command or '#' in command:
                        raise ValueError("Tasmota command contains dangerous pattern")
                    topic = f"cmnd/{device_name}/{command}"
                elif tasmota_type == 'stat':
                    # Status format: stat/device_name/status
                    topic = f"stat/{device_name}/status"
                else:  # tele
                    # Telemetry format: tele/device_name/telemetry
                    topic = f"tele/{device_name}/telemetry"
                
                # Validate constructed topic (additional safety check)
                # Note: topic is constructed from validated components, but double-check
                if not re.match(r'^[a-zA-Z0-9_\-\./]+$', topic):
                    raise ValueError("Invalid Tasmota topic format")
                if '..' in topic or '--' in topic or '+' in topic or '#' in topic:
                    raise ValueError("Tasmota topic contains dangerous pattern")
                
                # Tasmota expects JSON payload
                if not isinstance(payload, dict):
                    payload = {"data": payload}
                message = json.dumps(payload).encode('utf-8')
            
            # Apply topic prefix if configured (for device organization)
            topic_prefix = self.module_config.get('topic_prefix')
            if topic_prefix:
                # SECURITY: Validate prefix format and reject dangerous patterns
                if not isinstance(topic_prefix, str):
                    raise ValueError("Topic prefix must be a string")
                
                # Remove whitespace
                topic_prefix = topic_prefix.strip()
                
                if not topic_prefix:
                    raise ValueError("Topic prefix cannot be empty")
                
                # Reject dangerous patterns (path traversal, wildcards, etc.)
                if '..' in topic_prefix:
                    raise ValueError("Topic prefix contains dangerous pattern: '..' (path traversal not allowed)")
                if '--' in topic_prefix:
                    raise ValueError("Topic prefix contains dangerous pattern: '--' (not allowed)")
                if '+' in topic_prefix or '#' in topic_prefix:
                    raise ValueError("Topic prefix cannot contain wildcards (+ or #)")
                if topic_prefix.startswith('$'):
                    raise ValueError("Topic prefix cannot start with '$' (reserved for system topics)")
                if '//' in topic_prefix:
                    raise ValueError("Topic prefix cannot contain consecutive slashes")
                
                # Validate format: alphanumeric, underscore, hyphen, dot, and forward slash only
                if not re.match(r'^[a-zA-Z0-9_\-\./]+$', topic_prefix):
                    raise ValueError("Invalid topic prefix format")
                
                # Remove trailing slash if present
                topic_prefix = topic_prefix.rstrip('/')
                # Prepend to topic
                if topic.startswith('/'):
                    topic = topic_prefix + topic
                else:
                    topic = f"{topic_prefix}/{topic}"
            
            # Publish message
            await self.client.publish(
                topic=topic,
                payload=message,
                qos=qos,
                retain=retained
            )
            
            print(f"Message published to MQTT topic: {topic} (QoS: {qos}, Retained: {retained})")
            
        except Exception as e:
            # Log detailed error server-side
            print(f"Failed to publish message to MQTT: {e}")
            # Raise generic error to client (don't expose MQTT details)
            from src.utils import sanitize_error_message
            raise Exception(sanitize_error_message(e, "MQTT operation"))

