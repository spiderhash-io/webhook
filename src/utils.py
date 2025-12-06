import requests
import uuid
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
import asyncio
import logging
from typing import Any, Tuple, Optional, Tuple, Optional


def sanitize_error_message(error: Any, context: str = None) -> str:
    """
    Sanitize error messages to prevent information disclosure.
    
    This function removes sensitive information from error messages that
    will be sent to clients, while logging detailed information server-side.
    
    Args:
        error: The error object or error message string
        context: Optional context about where the error occurred
        
    Returns:
        Generic error message safe for client exposure
    """
    # Convert error to string if it's an exception
    if hasattr(error, '__str__'):
        error_str = str(error)
    else:
        error_str = str(error)
    
    # Log detailed error server-side (for debugging)
    if context:
        print(f"ERROR [{context}]: {error_str}")
    else:
        print(f"ERROR: {error_str}")
    
    # Return generic message for client
    # Don't expose:
    # - URLs, file paths, hostnames
    # - Module names, configuration details
    # - Internal error details
    # - Stack traces
    
    # Check for common sensitive patterns
    sensitive_patterns = [
        (r'http[s]?://[^\s]+', 'URL'),
        (r'file://[^\s]+', 'file path'),
        (r'/[^\s]+', 'file path'),
        (r'[a-zA-Z0-9_]+://[^\s]+', 'URL'),
        (r'localhost:\d+', 'service address'),
        (r'\d+\.\d+\.\d+\.\d+:\d+', 'service address'),
        (r'module[_\s]+[\w]+', 'module name'),
        (r'Failed to.*:\s*[^\n]+', 'error details'),
    ]
    
    # If error contains sensitive patterns, return generic message
    for pattern, pattern_type in sensitive_patterns:
        if re.search(pattern, error_str, re.IGNORECASE):
            if context:
                return f"Processing error occurred in {context}"
            return "An error occurred while processing the request"
    
    # For generic errors, return a safe message
    # Don't expose the actual error text
    if context:
        return f"Processing error occurred in {context}"
    return "An error occurred while processing the request"


def detect_encoding_from_content_type(content_type: Optional[str]) -> Optional[str]:
    """
    Detect encoding from Content-Type header.
    
    Args:
        content_type: Content-Type header value (e.g., "application/json; charset=utf-8")
        
    Returns:
        Encoding name if found, None otherwise
    """
    if not content_type:
        return None
    
    # Parse charset from Content-Type header
    # Format: "type/subtype; charset=encoding" or "type/subtype; charset='encoding'"
    charset_match = re.search(r'charset\s*=\s*["\']?([^"\'\s;]+)["\']?', content_type, re.IGNORECASE)
    if charset_match:
        return charset_match.group(1).lower()
    
    return None


def safe_decode_body(body: bytes, content_type: Optional[str] = None, default_encoding: str = 'utf-8') -> Tuple[str, str]:
    """
    Safely decode request body bytes to string with encoding detection and fallback.
    
    This function:
    - Detects encoding from Content-Type header if available
    - Falls back to common encodings (UTF-8, UTF-16, Latin-1, etc.)
    - Handles UnicodeDecodeError gracefully
    - Sanitizes error messages to prevent information disclosure
    
    Args:
        body: Request body as bytes
        content_type: Optional Content-Type header value
        default_encoding: Default encoding to use if detection fails (default: 'utf-8')
        
    Returns:
        Tuple of (decoded_string, encoding_used)
        
    Raises:
        HTTPException: If body cannot be decoded with any encoding
    """
    from fastapi import HTTPException
    
    # Try encoding from Content-Type header first
    detected_encoding = detect_encoding_from_content_type(content_type)
    
    # List of encodings to try (in order of preference)
    encodings_to_try = []
    
    if detected_encoding:
        encodings_to_try.append(detected_encoding)
    
    # Add common encodings as fallback
    common_encodings = ['utf-8', 'utf-16', 'utf-16le', 'utf-16be', 'latin-1', 'iso-8859-1', 'cp1252']
    for enc in common_encodings:
        if enc not in encodings_to_try:
            encodings_to_try.append(enc)
    
    # Try each encoding
    for encoding in encodings_to_try:
        try:
            decoded = body.decode(encoding)
            return decoded, encoding
        except (UnicodeDecodeError, LookupError):
            # LookupError for invalid encoding names
            continue
    
    # Final fallback: try default encoding with error handling
    try:
        # Use 'replace' error handling to get partial decode
        decoded = body.decode(default_encoding, errors='replace')
        # If we got here, return it but log a warning
        print(f"WARNING: Request body decoded with errors using {default_encoding}. Some characters may be lost.")
        return decoded, default_encoding
    except Exception:
        # If even this fails, raise an error
        raise HTTPException(
            status_code=400,
            detail="Request body encoding could not be determined or decoded. Please ensure the body is valid UTF-8 or specify charset in Content-Type header."
        )


def count_words_at_url(url):
    resp = requests.get(url)
    txt = len(resp.text.split())
    print(txt)
    return txt


async def save_to_disk(payload, config):
    my_uuid = uuid.uuid4()
    
    module_config = config.get('module-config', {})
    path = module_config.get('path', '.')
    
    if path != '.' and not os.path.exists(path):
        os.makedirs(path)

    file_path = os.path.join(path, f"{my_uuid}.txt")
    with open(file_path, mode="w") as f:
        f.write(str(payload))    
        f.flush()
        f.close()


async def print_to_stdout(payload, headers, config):
    print("config: "+str(config))
    print("headers: "+str(headers))
    print("body: "+str(payload))
    # await asyncio.sleep(5)  # Simulating delay


def _sanitize_env_value(value: str, context_key: str = None) -> str:
    """
    Sanitize environment variable value to prevent injection attacks.
    
    This function:
    - Removes or escapes dangerous characters that could be used for injection
    - Validates value format based on context
    - Prevents command injection, URL injection, and code injection
    
    Args:
        value: The environment variable value to sanitize
        context_key: Optional context key to determine validation rules
        
    Returns:
        Sanitized value
    """
    if not isinstance(value, str):
        return value
    
    original_value = value
    
    # Remove null bytes (always dangerous)
    if '\x00' in value:
        print(f"WARNING: Environment variable value contains null byte (context: {context_key}), removing")
        value = value.replace('\x00', '')
    
    # Check for URL injection patterns FIRST (if context suggests URL)
    # This must be done before command injection checks to catch schemes
    if context_key and ('url' in context_key.lower() or 'host' in context_key.lower()):
        # Check for dangerous URL schemes
        dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'gopher:']
        for scheme in dangerous_schemes:
            if value.lower().startswith(scheme):
                print(f"WARNING: Environment variable value contains dangerous URL scheme (context: {context_key}): {scheme}")
                # Remove the dangerous scheme
                value = value[len(scheme):].lstrip()
    
    # Check for command injection patterns - remove dangerous characters
    # Command separators and injection characters
    dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '{', '}']
    for char in dangerous_chars:
        if char in value:
            print(f"WARNING: Environment variable value contains dangerous character '{char}' (context: {context_key}): {value[:50]}")
            value = value.replace(char, '')
    
    # Check for SQL injection patterns (if context suggests SQL)
    if context_key and ('sql' in context_key.lower() or 'query' in context_key.lower() or 'table' in context_key.lower()):
        sql_injection_patterns = [
            r"';",  # SQL injection with single quote
            r'";',  # SQL injection with double quote
            r'--',  # SQL comment
            r'/\*',  # SQL comment start
            r'\*/',  # SQL comment end
            r'union\s+select',  # UNION SELECT
            r'drop\s+table',  # DROP TABLE
            r'delete\s+from',  # DELETE FROM
            r'insert\s+into',  # INSERT INTO
            r'update\s+set',  # UPDATE SET
        ]
        for pattern in sql_injection_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                print(f"WARNING: Environment variable value contains potential SQL injection pattern (context: {context_key}): {value[:50]}")
                # Remove SQL injection patterns
                value = re.sub(pattern, '', value, flags=re.IGNORECASE)
    
    # Check for path traversal patterns
    if '..' in value:
        print(f"WARNING: Environment variable value contains path traversal pattern (context: {context_key}): {value[:50]}")
        # Remove path traversal
        value = value.replace('..', '')
    
    # Check for absolute paths in non-path contexts
    if value.startswith('/') and context_key and 'path' not in context_key.lower() and 'url' not in context_key.lower():
        print(f"WARNING: Environment variable value contains absolute path (context: {context_key}): {value[:50]}")
        # Remove leading slash
        value = value.lstrip('/')
    
    # Remove common command injection keywords
    command_keywords = ['rm ', 'rm -rf', 'cat ', 'ls ', 'pwd', 'whoami', 'id', 'uname']
    for keyword in command_keywords:
        if keyword.lower() in value.lower():
            print(f"WARNING: Environment variable value contains command keyword '{keyword}' (context: {context_key}): {value[:50]}")
            # Remove the keyword and surrounding context
            value = re.sub(re.escape(keyword), '', value, flags=re.IGNORECASE)
    
    # Limit length to prevent DoS
    MAX_ENV_VALUE_LENGTH = 4096
    if len(value) > MAX_ENV_VALUE_LENGTH:
        print(f"WARNING: Environment variable value too long (context: {context_key}): {len(value)} characters, truncating")
        value = value[:MAX_ENV_VALUE_LENGTH]
    
    # If value became empty after sanitization, return a safe default
    if not value.strip() and original_value.strip():
        print(f"WARNING: Environment variable value was completely sanitized (context: {context_key}), using safe default")
        return 'sanitized_value'
    
    return value


def load_env_vars(data):
    """
    Load environment variables from configuration data.
    
    Supports multiple patterns:
    1. {$VAR} - Replace entire value with environment variable
    2. {$VAR:default} - Use environment variable or default value if not set
    3. Embedded variables in strings: "http://{$HOST}:{$PORT}"
    
    Examples:
        "host": "{$REDIS_HOST}" -> replaced with env var value
        "host": "{$REDIS_HOST:localhost}" -> replaced with env var or "localhost"
        "url": "http://{$HOST}:{$PORT}/api" -> replaced with env vars embedded in string
    
    Security: All environment variable values are sanitized to prevent injection attacks.
    
    Args:
        data: Configuration data (dict, list, or primitive)
        
    Returns:
        Data with environment variables replaced and sanitized
    """
    # Pattern 1: Exact match {$VAR} or {$VAR:default} (default can be empty)
    exact_pattern = re.compile(r'^\{\$(\w+)(?::(.*))?\}$')
    # Pattern 2: Embedded variables in strings {$VAR} or {$VAR:default}
    embedded_pattern = re.compile(r'\{\$(\w+)(?::([^}]*))?\}')

    def process_string(value, context_key=None):
        """Process a string value to replace environment variables."""
        # Try exact match first (entire string is a variable)
        exact_match = exact_pattern.match(value)
        if exact_match:
            env_var = exact_match.group(1)
            default = exact_match.group(2)  # Can be None or empty string
            env_value = os.getenv(env_var)
            
            if env_value is not None:
                # Sanitize environment variable value
                sanitized = _sanitize_env_value(env_value, context_key)
                return sanitized
            elif default is not None:  # Includes empty string
                # Sanitize default value as well
                sanitized = _sanitize_env_value(default, context_key)
                return sanitized
            else:
                # No default provided and env var not set
                print(f"Warning: Environment variable '{env_var}' not set and no default provided for key '{context_key}'")
                return f'Undefined variable {env_var}'
        else:
            # Try embedded variables (variables within strings)
            def replace_embedded(match):
                env_var = match.group(1)
                default = match.group(2)  # Can be None or empty string
                env_value = os.getenv(env_var)
                
                if env_value is not None:
                    # Sanitize environment variable value
                    sanitized = _sanitize_env_value(env_value, context_key)
                    return sanitized
                elif default is not None:  # Includes empty string
                    # Sanitize default value as well
                    sanitized = _sanitize_env_value(default, context_key)
                    return sanitized
                else:
                    # Keep original if not found and no default
                    print(f"Warning: Environment variable '{env_var}' not set in embedded string for key '{context_key}'")
                    return match.group(0)  # Return original placeholder
            
            # Replace all embedded variables
            new_value = embedded_pattern.sub(replace_embedded, value)
            return new_value

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = process_string(value, key)
            else:
                # Recursive call for nested dictionaries or lists
                load_env_vars(value)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, str):
                data[i] = process_string(item, f"list[{i}]")
            else:
                load_env_vars(item)

    return data


import redis.asyncio as redis
import time

class EndpointStats:
    def __init__(self):
        self.stats = defaultdict(lambda: defaultdict(int))
        self.timestamps = defaultdict(dict)  # Using dict for timestamps
        self.lock = asyncio.Lock()
        self.bucket_size = timedelta(minutes=1)  # Smallest bucket size

    async def increment(self, endpoint_name):
        async with self.lock:
            now = datetime.utcnow()
            bucket = self._get_bucket(now)
            self.timestamps[endpoint_name][bucket] = self.timestamps[endpoint_name].get(bucket, 0) + 1
            self.stats[endpoint_name]['total'] += 1
            self._cleanup_old_buckets(endpoint_name, now)  # Cleanup old buckets

    def _get_bucket(self, timestamp):
        # Align timestamp to the start of the bucket
        return timestamp - (timestamp - datetime.min) % self.bucket_size

    def _cleanup_old_buckets(self, endpoint_name, now):
        # Remove buckets older than a certain cutoff (e.g., 1 day)
        cutoff = now - timedelta(days=1)
        old_buckets = [time for time in self.timestamps[endpoint_name] if time < cutoff]
        for bucket in old_buckets:
            del self.timestamps[endpoint_name][bucket]

    def get_stats(self):
        stats_summary = defaultdict(dict)
        now = datetime.utcnow()
        for endpoint in self.timestamps:
            stats_summary[endpoint]['total'] = self.stats[endpoint]['total']
            stats_summary[endpoint]['minute'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(minutes=1))
            stats_summary[endpoint]['5_minutes'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(minutes=5))
            stats_summary[endpoint]['15_minutes'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(minutes=15))
            stats_summary[endpoint]['30_minutes'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(minutes=30))
            stats_summary[endpoint]['hour'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(hours=1))
            stats_summary[endpoint]['day'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(days=1))
            stats_summary[endpoint]['week'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(weeks=1))
            stats_summary[endpoint]['month'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(days=30))

        return stats_summary


class RedisEndpointStats:
    def __init__(self, redis_url=None):
        # Use REDIS_HOST env var if not provided, default to localhost
        if not redis_url:
            redis_host = os.getenv('REDIS_HOST', 'localhost')
            redis_port = os.getenv('REDIS_PORT', '6379')
            redis_url = f"redis://{redis_host}:{redis_port}"
        
        self._redis_url = redis_url
        self._redis = None
        self.bucket_size_seconds = 60  # 1 minute

    @property
    def redis(self):
        """Get Redis connection, creating it if needed."""
        if self._redis is None:
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
        return self._redis

    async def close(self):
        """Close the Redis connection."""
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                pass  # Ignore errors when closing
            finally:
                self._redis = None

    def _ensure_connection(self):
        """Ensure Redis connection is valid, recreate if needed."""
        if self._redis is None:
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
        return self._redis

    async def _reconnect_if_needed(self):
        """Reconnect Redis if connection is invalid."""
        if self._redis is None:
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
            return
        
        # Try to check if connection is still valid
        try:
            # This will raise an error if the connection is bound to a closed event loop
            await self._redis.ping()
        except (RuntimeError, AttributeError) as e:
            # Event loop is closed or connection is invalid, recreate it
            try:
                await self._redis.aclose()
            except Exception:
                pass
            self._redis = redis.from_url(self._redis_url, decode_responses=True)

    async def increment(self, endpoint_name):
        await self._reconnect_if_needed()
        now = int(time.time())
        bucket_timestamp = now - (now % self.bucket_size_seconds)
        
        # Use a pipeline for atomicity and performance
        try:
            async with self.redis.pipeline(transaction=True) as pipe:
                # Add endpoint to set of known endpoints
                pipe.sadd("stats:endpoints", endpoint_name)
                
                # Increment total counter
                pipe.incr(f"stats:{endpoint_name}:total")
                
                # Increment bucket counter
                bucket_key = f"stats:{endpoint_name}:bucket:{bucket_timestamp}"
                pipe.incr(bucket_key)
                
                # Set expiration for bucket (32 days to cover month stats)
                pipe.expire(bucket_key, 32 * 24 * 60 * 60)
                
                await pipe.execute()
        except (RuntimeError, AttributeError):
            # Connection issue, reconnect and retry once
            await self._reconnect_if_needed()
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.sadd("stats:endpoints", endpoint_name)
                pipe.incr(f"stats:{endpoint_name}:total")
                bucket_key = f"stats:{endpoint_name}:bucket:{bucket_timestamp}"
                pipe.incr(bucket_key)
                pipe.expire(bucket_key, 32 * 24 * 60 * 60)
                await pipe.execute()

    async def get_stats(self):
        await self._reconnect_if_needed()
        stats_summary = defaultdict(dict)
        now = int(time.time())
        
        # Get all known endpoints
        try:
            endpoints = await self.redis.smembers("stats:endpoints")
        except (RuntimeError, AttributeError):
            # Connection issue, reconnect and retry
            await self._reconnect_if_needed()
            endpoints = await self.redis.smembers("stats:endpoints")
        
        for endpoint in endpoints:
            # Get total
            total = await self.redis.get(f"stats:{endpoint}:total")
            stats_summary[endpoint]['total'] = int(total) if total else 0
            
            # Calculate windows
            windows = {
                'minute': 60,
                '5_minutes': 5 * 60,
                '15_minutes': 15 * 60,
                '30_minutes': 30 * 60,
                'hour': 3600,
                'day': 86400,
                'week': 7 * 86400,
                'month': 30 * 86400
            }
            
            # For each window, we need to sum relevant buckets
            # Optimization: For larger windows, this might be slow if we fetch all keys.
            # But for now, we'll fetch keys. 
            # To optimize, we could just fetch the keys we need.
            
            # Let's do it efficiently:
            # We need buckets from (now - window) to now.
            # We can generate the keys.
            
            # However, MGETing 43200 keys for 'month' is too much.
            # Maybe we should limit the precision for older stats or accept it's slow?
            # Or maybe we only calculate 'minute' to 'hour' accurately with buckets, 
            # and for larger windows we rely on a different aggregation?
            
            # Given the constraints, let's implement up to 'hour' or 'day' with full precision,
            # and maybe warn or approximate for larger? 
            # Actually, let's just implement it. If it's too slow, we'll see.
            # But wait, 'month' = 43200 minutes. MGET 43k keys is definitely bad.
            
            # Alternative: Maintain separate counters for larger windows?
            # e.g. stats:{endpoint}:hour_bucket:{hour_timestamp}
            # stats:{endpoint}:day_bucket:{day_timestamp}
            # This would require updating multiple keys on increment, but makes reading fast.
            # Let's update increment to support multi-resolution buckets.
            
            pass # Logic continues below in a better implementation
            
        # Re-implementing get_stats with multi-resolution buckets support would be better.
        # But let's stick to the interface. I'll update increment to write to multiple resolutions.
        return await self._get_stats_optimized()

    async def _get_stats_optimized(self):
        stats_summary = defaultdict(dict)
        endpoints = await self.redis.smembers("stats:endpoints")
        
        for endpoint in endpoints:
            # SECURITY: Validate endpoint names from Redis to prevent key manipulation
            # Even though increment validates, legacy entries or manual Redis modifications could exist
            if not endpoint or not isinstance(endpoint, str):
                continue  # Skip invalid endpoint names
            if len(endpoint) > 256:  # Same limit as increment
                continue  # Skip overly long endpoint names
            if '\x00' in endpoint or '\n' in endpoint or '\r' in endpoint:
                continue  # Skip endpoint names with dangerous characters
            
            total = await self.redis.get(f"stats:{endpoint}:total")
            stats_summary[endpoint]['total'] = int(total) if total else 0
            
            # We will use MGET to fetch values for different windows
            # But we need to define what keys we are looking for.
            # If we update increment to write to minute, hour, day buckets.
            
            # Let's assume we update increment to write to:
            # - minute bucket (TTL 2 hours)
            # - hour bucket (TTL 2 days)
            # - day bucket (TTL 32 days)
            
            # Then:
            # minute stats = sum(last 1 minute buckets)
            # 5_minutes = sum(last 5 minute buckets)
            # ...
            # hour = sum(last 60 minute buckets) -> or just use hour buckets? 
            # No, sliding window needs minute buckets for accuracy.
            # But "last hour" usually means "last 60 minutes".
            
            # Let's keep it simple for now. 
            # I will implement a helper to sum buckets.
            
            windows_config = [
                ('minute', 1, 60),
                ('5_minutes', 5, 60),
                ('15_minutes', 15, 60),
                ('30_minutes', 30, 60),
                ('hour', 60, 60),
                ('day', 24, 3600), # Use hour buckets for day
                ('week', 7, 86400), # Use day buckets for week
                ('month', 30, 86400) # Use day buckets for month
            ]
            
            # We need to fetch all necessary keys.
            keys_to_fetch = []
            now = int(time.time())
            
            # Helper to generate keys
            def get_keys(resolution_seconds, count):
                keys = []
                current_bucket = now - (now % resolution_seconds)
                for i in range(count):
                    t = current_bucket - (i * resolution_seconds)
                    keys.append(f"stats:{endpoint}:bucket:{resolution_seconds}:{t}")
                return keys

            # We need:
            # 60 minute buckets (covers minute, 5m, 15m, 30m, hour)
            # 24 hour buckets (covers day)
            # 30 day buckets (covers week, month)
            
            minute_keys = get_keys(60, 60)
            hour_keys = get_keys(3600, 24)
            day_keys = get_keys(86400, 30)
            
            all_keys = minute_keys + hour_keys + day_keys
            
            # MGET all
            if all_keys:
                values = await self.redis.mget(all_keys)
                
                # Map values back to keys
                data = dict(zip(all_keys, [int(v) if v else 0 for v in values]))
                
                # Calculate stats
                def sum_keys(keys):
                    return sum(data.get(k, 0) for k in keys)
                
                stats_summary[endpoint]['minute'] = sum_keys(minute_keys[:1])
                stats_summary[endpoint]['5_minutes'] = sum_keys(minute_keys[:5])
                stats_summary[endpoint]['15_minutes'] = sum_keys(minute_keys[:15])
                stats_summary[endpoint]['30_minutes'] = sum_keys(minute_keys[:30])
                stats_summary[endpoint]['hour'] = sum_keys(minute_keys[:60])
                
                stats_summary[endpoint]['day'] = sum_keys(hour_keys[:24])
                stats_summary[endpoint]['week'] = sum_keys(day_keys[:7])
                stats_summary[endpoint]['month'] = sum_keys(day_keys[:30])

        return stats_summary

    async def increment_multi_resolution(self, endpoint_name):
        # SECURITY: Validate endpoint_name to prevent key manipulation and DoS
        if not endpoint_name or not isinstance(endpoint_name, str):
            raise ValueError("endpoint_name must be a non-empty string")
        
        endpoint_name = endpoint_name.strip()
        if not endpoint_name:
            raise ValueError("endpoint_name cannot be empty or whitespace-only")
        
        # SECURITY: Limit endpoint name length to prevent DoS via large keys
        MAX_ENDPOINT_NAME_LENGTH = 256  # Reasonable limit for Redis keys
        if len(endpoint_name) > MAX_ENDPOINT_NAME_LENGTH:
            raise ValueError(f"endpoint_name too long: {len(endpoint_name)} characters (max: {MAX_ENDPOINT_NAME_LENGTH})")
        
        # SECURITY: Check for null bytes (dangerous in keys)
        if '\x00' in endpoint_name:
            raise ValueError("endpoint_name cannot contain null bytes")
        
        # SECURITY: Check for newlines/carriage returns (could cause issues)
        if '\n' in endpoint_name or '\r' in endpoint_name:
            raise ValueError("endpoint_name cannot contain newlines or carriage returns")
        
        await self._reconnect_if_needed()
        now = int(time.time())
        
        try:
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.sadd("stats:endpoints", endpoint_name)
                pipe.incr(f"stats:{endpoint_name}:total")
                
                # Minute bucket
                minute_ts = now - (now % 60)
                pipe.incr(f"stats:{endpoint_name}:bucket:60:{minute_ts}")
                pipe.expire(f"stats:{endpoint_name}:bucket:60:{minute_ts}", 7200) # 2 hours
                
                # Hour bucket
                hour_ts = now - (now % 3600)
                pipe.incr(f"stats:{endpoint_name}:bucket:3600:{hour_ts}")
                pipe.expire(f"stats:{endpoint_name}:bucket:3600:{hour_ts}", 172800) # 2 days
                
                # Day bucket
                day_ts = now - (now % 86400)
                pipe.incr(f"stats:{endpoint_name}:bucket:86400:{day_ts}")
                pipe.expire(f"stats:{endpoint_name}:bucket:86400:{day_ts}", 3000000) # ~35 days
                
                await pipe.execute()
        except (RuntimeError, AttributeError):
            # Connection issue, reconnect and retry once
            await self._reconnect_if_needed()
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.sadd("stats:endpoints", endpoint_name)
                pipe.incr(f"stats:{endpoint_name}:total")
                minute_ts = now - (now % 60)
                pipe.incr(f"stats:{endpoint_name}:bucket:60:{minute_ts}")
                pipe.expire(f"stats:{endpoint_name}:bucket:60:{minute_ts}", 7200)
                hour_ts = now - (now % 3600)
                pipe.incr(f"stats:{endpoint_name}:bucket:3600:{hour_ts}")
                pipe.expire(f"stats:{endpoint_name}:bucket:3600:{hour_ts}", 172800)
                day_ts = now - (now % 86400)
                pipe.incr(f"stats:{endpoint_name}:bucket:86400:{day_ts}")
                pipe.expire(f"stats:{endpoint_name}:bucket:86400:{day_ts}", 3000000)
                await pipe.execute()

    # Override increment to use multi-resolution
    async def increment(self, endpoint_name):
        await self.increment_multi_resolution(endpoint_name)

    async def _cleanup_old_buckets(self, endpoint_name, now):
        # Redis handles expiration automatically
        pass


# SECRET_KEY = "your-secret-key"  # Replace with your secret key

# def verify_hmac(body, received_signature):
#     """
#     Verify HMAC signature of the request body.
#     """
#     # Create a new hmac object using the secret key and the SHA256 hash function
#     hmac_obj = hmac.new(SECRET_KEY.encode(), body, hashlib.sha256)
#     # Compute the HMAC signature
#     computed_signature = hmac_obj.hexdigest()
#     # Compare the computed signature with the received signature
#     return hmac.compare_digest(computed_signature, received_signature)


# async def your_endpoint(request: Request, x_hmac_signature: str = Header(None)):
#     # Read the request body
#     body = await request.body()
#
#     # Verify HMAC
#     if not verify_hmac(body, x_hmac_signature):
#         raise HTTPException(status_code=401, detail="Invalid HMAC signature")
