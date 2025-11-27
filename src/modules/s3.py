import json
import uuid
import re
import os
from datetime import datetime
from typing import Any, Dict
import boto3
from botocore.exceptions import ClientError
from src.modules.base import BaseModule


class S3Module(BaseModule):
    """Module for saving webhook payloads to AWS S3."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.s3_client = None
        # Validate prefix and filename_pattern during initialization
        raw_prefix = self.module_config.get('prefix', 'webhooks')
        raw_filename_pattern = self.module_config.get('filename_pattern', 'webhook_{uuid}.json')
        self._validated_prefix = self._validate_s3_path_component(raw_prefix, 'prefix')
        self._validated_filename_pattern = self._validate_filename_pattern(raw_filename_pattern)
    
    def _validate_s3_path_component(self, path_component: str, component_name: str) -> str:
        """
        Validate and sanitize S3 path component (prefix or path segment) to prevent path traversal.
        
        Args:
            path_component: The path component to validate
            component_name: Name of the component for error messages
            
        Returns:
            Validated and sanitized path component
            
        Raises:
            ValueError: If path component is invalid or contains dangerous characters
        """
        if not path_component or not isinstance(path_component, str):
            raise ValueError(f"{component_name} must be a non-empty string")
        
        # Remove whitespace
        path_component = path_component.strip()
        
        if not path_component:
            raise ValueError(f"{component_name} cannot be empty")
        
        # Maximum length to prevent DoS (S3 key limit is 1024 bytes, but we'll be more restrictive)
        if len(path_component) > 255:
            raise ValueError(f"{component_name} too long: {len(path_component)} characters (max: 255)")
        
        # Reject path traversal sequences
        if '..' in path_component or path_component.startswith('/') or path_component.endswith('/'):
            raise ValueError(f"{component_name} contains path traversal or invalid characters: '{path_component}'")
        
        # Validate format: alphanumeric, underscore, hyphen, and forward slash (for nested paths)
        # But no consecutive slashes or leading/trailing slashes
        if not re.match(r'^[a-zA-Z0-9_\-/]+$', path_component):
            raise ValueError(
                f"Invalid {component_name} format: '{path_component}'. "
                f"Only alphanumeric characters, underscores, hyphens, and forward slashes are allowed."
            )
        
        # Reject dangerous patterns
        dangerous_patterns = ['//', '--', ';', '|', '&', '$', '`', '\\', ':', '@', '#', '%', '?', '*']
        for pattern in dangerous_patterns:
            if pattern in path_component:
                raise ValueError(f"{component_name} contains dangerous pattern: '{pattern}'")
        
        # Reject control characters
        if any(char in path_component for char in ['\r', '\n', '\0', '\t']):
            raise ValueError(f"{component_name} contains forbidden control characters")
        
        # Normalize: remove any leading/trailing slashes and collapse multiple slashes
        path_component = re.sub(r'/+', '/', path_component)
        path_component = path_component.strip('/')
        
        return path_component
    
    def _validate_filename_pattern(self, filename_pattern: str) -> str:
        """
        Validate and sanitize filename pattern to prevent injection.
        
        Args:
            filename_pattern: The filename pattern from configuration
            
        Returns:
            Validated and sanitized filename pattern
            
        Raises:
            ValueError: If filename pattern is invalid
        """
        if not filename_pattern or not isinstance(filename_pattern, str):
            raise ValueError("Filename pattern must be a non-empty string")
        
        # Remove whitespace
        filename_pattern = filename_pattern.strip()
        
        if not filename_pattern:
            raise ValueError("Filename pattern cannot be empty")
        
        # Maximum length
        if len(filename_pattern) > 255:
            raise ValueError(f"Filename pattern too long: {len(filename_pattern)} characters (max: 255)")
        
        # Reject path traversal
        if '..' in filename_pattern or '/' in filename_pattern or '\\' in filename_pattern:
            raise ValueError(f"Filename pattern contains path traversal or invalid characters: '{filename_pattern}'")
        
        # Allow only safe characters and placeholders
        # Placeholders: {uuid}, {timestamp}
        # Remove placeholders temporarily for validation
        temp_pattern = filename_pattern
        temp_pattern = temp_pattern.replace('{uuid}', '')
        temp_pattern = temp_pattern.replace('{timestamp}', '')
        
        # Validate remaining characters
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', temp_pattern):
            raise ValueError(
                f"Invalid filename pattern format: '{filename_pattern}'. "
                f"Only alphanumeric characters, underscores, hyphens, dots, and placeholders ({{uuid}}, {{timestamp}}) are allowed."
            )
        
        # Reject dangerous patterns
        dangerous_patterns = ['--', ';', '|', '&', '$', '`', ':', '@', '#', '%', '?', '*']
        for pattern in dangerous_patterns:
            if pattern in filename_pattern:
                raise ValueError(f"Filename pattern contains dangerous pattern: '{pattern}'")
        
        # Reject control characters
        if any(char in filename_pattern for char in ['\r', '\n', '\0', '\t']):
            raise ValueError("Filename pattern contains forbidden control characters")
        
        return filename_pattern
    
    def _validate_object_key(self, object_key: str) -> str:
        """
        Validate the final S3 object key to ensure it's safe.
        
        Args:
            object_key: The complete S3 object key
            
        Returns:
            Validated object key
            
        Raises:
            ValueError: If object key is invalid
        """
        if not object_key or not isinstance(object_key, str):
            raise ValueError("Object key must be a non-empty string")
        
        # S3 key length limit is 1024 bytes
        if len(object_key.encode('utf-8')) > 1024:
            raise ValueError(f"Object key too long: {len(object_key.encode('utf-8'))} bytes (max: 1024)")
        
        # Reject path traversal
        if '..' in object_key:
            raise ValueError(f"Object key contains path traversal: '{object_key}'")
        
        # Reject absolute paths
        if object_key.startswith('/'):
            raise ValueError(f"Object key cannot start with '/': '{object_key}'")
        
        # Reject control characters
        if any(char in object_key for char in ['\r', '\n', '\0', '\t']):
            raise ValueError("Object key contains forbidden control characters")
        
        return object_key
    
    async def setup(self) -> None:
        """Initialize S3 client."""
        aws_access_key = self.connection_details.get('aws_access_key_id')
        aws_secret_key = self.connection_details.get('aws_secret_access_key')
        region = self.connection_details.get('region', 'us-east-1')
        
        if aws_access_key and aws_secret_key:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
        else:
            # Use default credentials (IAM role, environment variables, etc.)
            self.s3_client = boto3.client('s3', region_name=region)
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Save payload to S3 bucket."""
        # Initialize client if not already done
        if not self.s3_client:
            await self.setup()
        
        bucket = self.module_config.get('bucket')
        if not bucket:
            raise Exception("S3 bucket not specified in module-config")
        
        # Generate object key using validated components
        prefix = self._validated_prefix
        timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H')
        filename_pattern = self._validated_filename_pattern
        
        # Replace placeholders in filename pattern
        filename = filename_pattern.replace('{uuid}', str(uuid.uuid4()))
        # Replace timestamp and sanitize (ISO format contains colons which are not allowed)
        timestamp_str = datetime.utcnow().isoformat().replace(':', '-').replace('+', '-')
        filename = filename.replace('{timestamp}', timestamp_str)
        
        # Validate filename after placeholder replacement
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
            raise ValueError(f"Generated filename contains invalid characters: '{filename}'")
        
        # Construct object key
        object_key = f"{prefix}/{timestamp}/{filename}"
        
        # Validate final object key
        object_key = self._validate_object_key(object_key)
        
        # Prepare content
        content_type = self.module_config.get('content_type', 'application/json')
        
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload, indent=2)
        else:
            body = str(payload)
        
        # Prepare metadata
        metadata = {}
        if self.module_config.get('include_headers', False):
            # S3 metadata keys must be lowercase and alphanumeric
            for key, value in headers.items():
                safe_key = key.lower().replace('-', '_')
                if safe_key.isalnum() or '_' in safe_key:
                    metadata[safe_key] = value[:1024]  # S3 metadata value limit
        
        try:
            # Upload to S3
            self.s3_client.put_object(
                Bucket=bucket,
                Key=object_key,
                Body=body.encode('utf-8'),
                ContentType=content_type,
                Metadata=metadata
            )
            
            print(f"Webhook payload saved to S3: s3://{bucket}/{object_key}")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            print(f"Failed to save to S3: {error_code} - {error_message}")
            raise Exception(f"S3 upload failed: {error_message}")
        except Exception as e:
            print(f"Failed to save to S3: {e}")
            raise e
