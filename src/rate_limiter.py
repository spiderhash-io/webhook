import time
from collections import defaultdict, deque
from typing import Dict, Tuple
import asyncio


class RateLimiter:
    """
    Rate limiter using sliding window algorithm.
    Tracks requests per webhook ID.
    """

    def __init__(self):
        # Store timestamps for each webhook_id
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.lock = asyncio.Lock()

    async def is_allowed(
        self, webhook_id: str, max_requests: int, window_seconds: int
    ) -> Tuple[bool, str]:
        """
        Check if request is allowed based on rate limit.

        Args:
            webhook_id: The webhook identifier
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds

        Returns:
            Tuple of (is_allowed, message)
        """
        async with self.lock:
            now = time.time()
            cutoff = now - window_seconds

            # Remove old requests outside the window
            while self.requests[webhook_id] and self.requests[webhook_id][0] < cutoff:
                self.requests[webhook_id].popleft()

            # Check if limit exceeded
            # SECURITY: If max_requests is 0, block all requests
            if max_requests == 0:
                return False, "Rate limit exceeded. No requests allowed"

            # Check if limit exceeded (deque cannot be empty if len >= max_requests > 0)
            if len(self.requests[webhook_id]) >= max_requests:
                oldest_request = self.requests[webhook_id][0]
                retry_after = int(oldest_request + window_seconds - now)
                return False, f"Rate limit exceeded. Retry after {retry_after} seconds"

            # Add current request
            self.requests[webhook_id].append(now)

            return True, "Request allowed"

    async def check_rate_limit(
        self, key: str, max_requests: int, window_seconds: int
    ) -> Tuple[bool, int]:
        """
        Check if request is allowed based on rate limit and return remaining.

        Args:
            key: The identifier for rate limiting (e.g., IP address, webhook ID)
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds

        Returns:
            Tuple of (is_allowed, remaining_requests)
        """
        async with self.lock:
            now = time.time()
            cutoff = now - window_seconds

            # Remove old requests outside the window
            while self.requests[key] and self.requests[key][0] < cutoff:
                self.requests[key].popleft()

            # Check if limit exceeded
            if max_requests == 0:
                return False, 0

            current_count = len(self.requests[key])

            if current_count >= max_requests:
                # Rate limit exceeded
                return False, 0

            # Add current request
            self.requests[key].append(now)

            # Calculate remaining (after adding current request)
            remaining = max(0, max_requests - (current_count + 1))
            return True, remaining

    async def cleanup_old_entries(self, max_age_seconds: int = 3600):
        """
        Cleanup old entries to prevent memory bloat.
        Should be called periodically.
        """
        async with self.lock:
            now = time.time()
            cutoff = now - max_age_seconds

            # Remove webhook IDs with no recent requests
            to_remove = []
            for webhook_id, requests in self.requests.items():
                # Remove old requests
                while requests and requests[0] < cutoff:
                    requests.popleft()

                # If no requests left, mark for removal
                if not requests:
                    to_remove.append(webhook_id)

            for webhook_id in to_remove:
                del self.requests[webhook_id]


# Global rate limiter instance
rate_limiter = RateLimiter()
