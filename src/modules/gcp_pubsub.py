"""
Google Cloud Pub/Sub module for publishing webhook payloads to GCP Pub/Sub topics.
"""
import json
import re
import base64
import asyncio
from typing import Any, Dict, Optional
from src.modules.base import BaseModule
from src.utils import sanitize_error_message

try:
    from google.cloud import pubsub_v1
    from google.api_core import exceptions
    GCP_PUBSUB_AVAILABLE = True
except ImportError:
    GCP_PUBSUB_AVAILABLE = False


class GCPPubSubModule(BaseModule):
    """Module for publishing webhook payloads to Google Cloud Pub/Sub topics."""
    
    def __init__(self, config: Dict[str, Any], **kwargs):
        super().__init__(config, **kwargs)
        if not GCP_PUBSUB_AVAILABLE:
            raise ImportError("google-cloud-pubsub library is required for GCP Pub/Sub module. Install with: pip install google-cloud-pubsub")
        
        self.publisher: Optional[pubsub_v1.PublisherClient] = None
        
        # Validate topic name during initialization
        raw_topic = self.module_config.get('topic')
        if raw_topic is not None:
            self._validated_topic = self._validate_topic_name(raw_topic)
        else:
            self._validated_topic = None
        
        # Get project ID
        self.project_id = self.connection_details.get('project_id')
        if not self.project_id:
            raise ValueError("project_id is required in connection details")
        
        # Validate project ID
        self._validate_project_id(self.project_id)
    
    def _validate_topic_name(self, topic_name: str) -> str:
        """
        Validate GCP Pub/Sub topic name to prevent injection.
        
        Args:
            topic_name: The topic name (without project prefix)
            
        Returns:
            Validated topic name
            
        Raises:
            ValueError: If topic name is invalid or contains dangerous characters
        """
        if not topic_name or not isinstance(topic_name, str):
            raise ValueError("Topic name must be a non-empty string")
        
        topic_name = topic_name.strip()
        
        if not topic_name:
            raise ValueError("Topic name cannot be empty")
        
        # Maximum length to prevent DoS (GCP limit is 255 chars)
        MAX_TOPIC_LENGTH = 255
        if len(topic_name) > MAX_TOPIC_LENGTH:
            raise ValueError(f"Topic name too long: {len(topic_name)} characters (max: {MAX_TOPIC_LENGTH})")
        
        # GCP topic names: lowercase letters, numbers, hyphens, underscores
        # Must start with a letter
        if not re.match(r'^[a-z][a-z0-9-_]*$', topic_name):
            raise ValueError(
                f"Invalid topic name format: '{topic_name}'. "
                f"Must start with a lowercase letter and contain only lowercase letters, numbers, hyphens, and underscores."
            )
        
        # Reject dangerous patterns
        dangerous_patterns = ['..', '--', '__', ';', '|', '&', '$', '`', '\\', '/', '(', ')', '[', ']', '{', '}']
        for pattern in dangerous_patterns:
            if pattern in topic_name:
                raise ValueError(f"Topic name contains dangerous pattern: '{pattern}'")
        
        # Reject control characters
        if any(char in topic_name for char in ['\r', '\n', '\0', '\t']):
            raise ValueError("Topic name contains forbidden control characters")
        
        return topic_name
    
    def _validate_project_id(self, project_id: str) -> None:
        """Validate GCP project ID."""
        if not project_id or not isinstance(project_id, str):
            raise ValueError("Project ID must be a non-empty string")
        
        project_id = project_id.strip()
        
        if not project_id:
            raise ValueError("Project ID cannot be empty")
        
        # GCP project IDs: lowercase letters, numbers, hyphens (6-30 chars)
        if not re.match(r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$', project_id):
            raise ValueError(
                f"Invalid project ID format: '{project_id}'. "
                f"Must be 6-30 characters, start with a lowercase letter, and contain only lowercase letters, numbers, and hyphens."
            )
    
    async def setup(self) -> None:
        """Initialize GCP Pub/Sub publisher client."""
        if not self._validated_topic:
            raise ValueError("Topic name is required and must be validated")
        
        try:
            # Get credentials from connection details (optional - can use default credentials)
            credentials_path = self.connection_details.get('credentials_path')
            
            if credentials_path:
                # SECURITY: Validate credentials path to prevent path traversal
                # URL decode to catch encoded traversal attempts
                import urllib.parse
                try:
                    # Decode URL-encoded characters (e.g., %2F -> /, %2E -> .)
                    decoded_path = urllib.parse.unquote(credentials_path)
                    # SECURITY: Decode again to catch double-encoded attacks (e.g., %252e -> %2e -> .)
                    if '%' in decoded_path:
                        decoded_path = urllib.parse.unquote(decoded_path)
                except Exception:
                    # If decoding fails, use original path
                    decoded_path = credentials_path
                
                # Check for traversal sequences in both original and decoded paths
                if '..' in credentials_path or '..' in decoded_path:
                    raise ValueError("Invalid credentials path (path traversal detected)")
                
                # Block absolute paths
                if credentials_path.startswith('/') or decoded_path.startswith('/'):
                    raise ValueError("Invalid credentials path (absolute path not allowed)")
                
                # Block null bytes
                if '\x00' in credentials_path or '\x00' in decoded_path:
                    raise ValueError("Invalid credentials path (null byte detected)")
                
                # Block Windows-style absolute paths
                if len(credentials_path) >= 2 and credentials_path[1] == ':':
                    raise ValueError("Invalid credentials path (Windows absolute path not allowed)")
                
                # Block backslashes (Windows path separator)
                if '\\' in credentials_path or '\\' in decoded_path:
                    raise ValueError("Invalid credentials path (backslash not allowed)")
                
                from google.oauth2 import service_account
                credentials = service_account.Credentials.from_service_account_file(credentials_path)
                self.publisher = pubsub_v1.PublisherClient(credentials=credentials)
            else:
                # Use default credentials (from environment or GCP metadata service)
                self.publisher = pubsub_v1.PublisherClient()
        except Exception as e:
            raise Exception(sanitize_error_message(e, "GCP Pub/Sub client creation"))
    
    async def teardown(self) -> None:
        """Close GCP Pub/Sub publisher client."""
        # GCP clients don't need explicit cleanup
        self.publisher = None
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Publish payload to GCP Pub/Sub topic."""
        if not self.publisher:
            await self.setup()
        
        try:
            # Serialize payload to JSON
            # SECURITY: Catch RecursionError for deeply nested structures
            if isinstance(payload, (dict, list)):
                try:
                    message_data = json.dumps(payload).encode('utf-8')
                except RecursionError:
                    # Deeply nested structure exceeds recursion limit - use simplified representation
                    message_data = json.dumps({"error": "Payload too deeply nested to serialize", "type": type(payload).__name__}).encode('utf-8')
            else:
                message_data = str(payload).encode('utf-8')
            
            # Construct full topic path
            topic_path = self.publisher.topic_path(self.project_id, self._validated_topic)
            
            # Convert headers to Pub/Sub attributes (string key-value pairs)
            attributes = {}
            for key, value in headers.items():
                if isinstance(value, str) and len(value) <= 1024:  # Pub/Sub attribute value limit
                    # Pub/Sub attribute keys must be valid
                    if re.match(r'^[a-zA-Z0-9_-]+$', key):
                        attributes[key] = value
            
            # Publish message (Pub/Sub publish is synchronous but returns a future)
            try:
                future = self.publisher.publish(topic_path, message_data, **attributes)
                # Wait for publish to complete (run in executor to avoid blocking)
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: future.result(timeout=10.0))
            except exceptions.NotFound:
                # Topic doesn't exist - try to create it (for development/testing with emulator)
                try:
                    print(f"Topic '{self._validated_topic}' not found, attempting to create it...")
                    # Create topic using the publisher client
                    def create_topic():
                        self.publisher.create_topic(request={"name": topic_path})
                    
                    await loop.run_in_executor(None, create_topic)
                    print(f"Created topic '{self._validated_topic}' in project '{self.project_id}'")
                    
                    # Retry publishing after topic creation
                    future = self.publisher.publish(topic_path, message_data, **attributes)
                    await loop.run_in_executor(None, lambda: future.result(timeout=10.0))
                    print(f"Published message to GCP Pub/Sub topic '{self._validated_topic}'")
                except Exception as create_error:
                    # If creation fails, raise original NotFound error
                    sanitized_error = sanitize_error_message(create_error, "GCP Pub/Sub topic creation")
                    print(f"ERROR [GCP Pub/Sub topic creation]: {sanitized_error}")
                    raise Exception(f"Topic '{self._validated_topic}' not found in project '{self.project_id}' and could not be created: {sanitized_error}")
        except Exception as e:
            # Check if it's already a sanitized error from above
            if "Topic" in str(e) and "not found" in str(e):
                raise e
            raise Exception(sanitize_error_message(e, "GCP Pub/Sub message publishing"))

