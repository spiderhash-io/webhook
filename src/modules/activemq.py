"""
Apache ActiveMQ module for publishing webhook payloads to ActiveMQ queues/topics.
"""
import json
import re
from typing import Any, Dict, Optional
from src.modules.base import BaseModule
from src.utils import sanitize_error_message

try:
    import stomp
    import asyncio
    ACTIVEMQ_AVAILABLE = True
except ImportError:
    ACTIVEMQ_AVAILABLE = False


class ActiveMQModule(BaseModule):
    """Module for publishing webhook payloads to Apache ActiveMQ."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        if not ACTIVEMQ_AVAILABLE:
            raise ImportError("stomp.py library is required for ActiveMQ module. Install with: pip install stomp.py")
        
        self.client: Optional[stomp.Connection] = None
        
        # Validate destination (queue or topic) during initialization
        raw_destination = self.module_config.get('destination')
        if raw_destination is not None:
            self._validated_destination = self._validate_destination(raw_destination)
        else:
            self._validated_destination = None
        
        # Destination type: queue or topic
        self.destination_type = self.module_config.get('destination_type', 'queue').lower()
        if self.destination_type not in ['queue', 'topic']:
            raise ValueError("destination_type must be 'queue' or 'topic'")
    
    def _validate_destination(self, destination: str) -> str:
        """
        Validate ActiveMQ destination name to prevent injection.
        
        Args:
            destination: The queue or topic name
            
        Returns:
            Validated destination name
            
        Raises:
            ValueError: If destination is invalid or contains dangerous characters
        """
        if not destination or not isinstance(destination, str):
            raise ValueError("Destination must be a non-empty string")
        
        destination = destination.strip()
        
        if not destination:
            raise ValueError("Destination cannot be empty")
        
        # Maximum length to prevent DoS
        MAX_DESTINATION_LENGTH = 255
        if len(destination) > MAX_DESTINATION_LENGTH:
            raise ValueError(f"Destination too long: {len(destination)} characters (max: {MAX_DESTINATION_LENGTH})")
        
        # Validate format: alphanumeric, underscore, hyphen, dot, and colon only
        if not re.match(r'^[a-zA-Z0-9_\-\.:]+$', destination):
            raise ValueError(
                f"Invalid destination format: '{destination}'. "
                f"Only alphanumeric characters, underscores, hyphens, dots, and colons are allowed."
            )
        
        # Reject dangerous patterns
        dangerous_patterns = ['..', '--', ';', '/*', '*/', '(', ')', '[', ']', '{', '}', '|', '&', '$', '`', '\\', '/']
        for pattern in dangerous_patterns:
            if pattern in destination:
                raise ValueError(f"Destination contains dangerous pattern: '{pattern}'")
        
        # Reject ActiveMQ reserved prefixes
        reserved_prefixes = ['ActiveMQ.', 'VirtualTopic.', 'Consumer.', 'Queue.', 'Topic.']
        destination_lower = destination.lower()
        for prefix in reserved_prefixes:
            if destination_lower.startswith(prefix.lower()):
                raise ValueError(f"Destination cannot start with reserved prefix: '{prefix}'")
        
        # Reject control characters
        if any(char in destination for char in ['\r', '\n', '\0', '\t']):
            raise ValueError("Destination contains forbidden control characters")
        
        return destination
    
    async def setup(self) -> None:
        """Initialize ActiveMQ connection."""
        if not self._validated_destination:
            raise ValueError("Destination is required and must be validated")
        
        try:
            host = self.connection_details.get('host', 'localhost')
            port = self.connection_details.get('port', 61613)
            user = self.connection_details.get('user', '')
            password = self.connection_details.get('password', '')
            
            # SECURITY: Validate host to prevent SSRF
            if not host or not isinstance(host, str):
                raise ValueError("Host must be a non-empty string")
            
            # Block private IPs and localhost (unless explicitly allowed)
            blocked_hosts = ['127.0.0.1', 'localhost', '0.0.0.0', '::1']
            if host.lower() in blocked_hosts:
                raise ValueError(f"Host '{host}' is blocked for security")
            
            # Validate port
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError(f"Port must be between 1 and 65535, got: {port}")
            
            # Create STOMP connection (stomp.py is synchronous, wrap in executor)
            loop = asyncio.get_event_loop()
            
            def create_connection():
                conn = stomp.Connection([(host, port)])
                if user and password:
                    conn.connect(user, password, wait=True)
                else:
                    conn.connect(wait=True)
                return conn
            
            self.client = await loop.run_in_executor(None, create_connection)
        except Exception as e:
            raise Exception(sanitize_error_message(e, "ActiveMQ connection"))
    
    async def teardown(self) -> None:
        """Close ActiveMQ connection."""
        if self.client:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.client.disconnect)
            except Exception:
                pass
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Publish payload to ActiveMQ destination."""
        if not self.client:
            await self.setup()
        
        try:
            # Serialize payload to JSON
            if isinstance(payload, (dict, list)):
                message = json.dumps(payload)
            else:
                message = str(payload)
            
            # Determine destination prefix
            if self.destination_type == 'queue':
                destination = f"/queue/{self._validated_destination}"
            else:
                destination = f"/topic/{self._validated_destination}"
            
            # Send message (stomp.py is synchronous, wrap in executor)
            loop = asyncio.get_event_loop()
            
            def send_message():
                # Convert headers dict to STOMP headers format
                stomp_headers = {}
                for key, value in headers.items():
                    if isinstance(value, str):
                        stomp_headers[key] = value
                self.client.send(destination, message, headers=stomp_headers)
            
            await loop.run_in_executor(None, send_message)
        except Exception as e:
            raise Exception(sanitize_error_message(e, "ActiveMQ message publishing"))

