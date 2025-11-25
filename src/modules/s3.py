import json
import uuid
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
        
        # Generate object key
        prefix = self.module_config.get('prefix', 'webhooks')
        timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H')
        filename = self.module_config.get('filename_pattern', 'webhook_{uuid}.json')
        
        # Replace placeholders
        filename = filename.replace('{uuid}', str(uuid.uuid4()))
        filename = filename.replace('{timestamp}', datetime.utcnow().isoformat())
        
        object_key = f"{prefix}/{timestamp}/{filename}"
        
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
