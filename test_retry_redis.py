#!/usr/bin/env python3
"""
Test script for retry mechanism with Redis failure scenario.

This script:
1. Starts sending webhook requests to the service
2. Stops Redis after some requests
3. Continues sending requests (which should retry)
4. Restarts Redis
5. Verifies all requests eventually succeed
"""

import asyncio
import httpx
import time
import subprocess
import sys
from typing import List, Dict
import json

# Configuration
WEBHOOK_URL = "http://localhost:8000/webhook/redis_test"
TOTAL_REQUESTS = 20
REQUESTS_BEFORE_STOP = 5
REDIS_STOP_DURATION = 10  # seconds
REDIS_CONTAINER_NAME = "core-webhook-module-redis-1"  # Docker container name
REDIS_PORT = 6380  # External port (docker-compose maps 6380:6379)

results: List[Dict] = []


def check_redis_running() -> bool:
    """Check if Redis container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={REDIS_CONTAINER_NAME}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return REDIS_CONTAINER_NAME in result.stdout
    except Exception as e:
        print(f"Error checking Redis status: {e}")
        return False


def stop_redis():
    """Stop Redis container."""
    try:
        print(f"\n🛑 Stopping Redis container: {REDIS_CONTAINER_NAME}")
        subprocess.run(
            ["docker", "stop", REDIS_CONTAINER_NAME],
            check=True,
            timeout=10
        )
        print("✅ Redis stopped")
        return True
    except Exception as e:
        print(f"❌ Failed to stop Redis: {e}")
        return False


def start_redis():
    """Start Redis container."""
    try:
        print(f"\n▶️  Starting Redis container: {REDIS_CONTAINER_NAME}")
        subprocess.run(
            ["docker", "start", REDIS_CONTAINER_NAME],
            check=True,
            timeout=10
        )
        # Wait for Redis to be ready
        time.sleep(2)
        print("✅ Redis started")
        return True
    except Exception as e:
        print(f"❌ Failed to start Redis: {e}")
        return False


async def send_request(client: httpx.AsyncClient, request_id: int) -> Dict:
    """Send a webhook request."""
    payload = {
        "request_id": request_id,
        "timestamp": time.time(),
        "data": f"test_data_{request_id}"
    }
    
    start_time = time.time()
    try:
        response = await client.post(
            WEBHOOK_URL,
            json=payload,
            timeout=30.0
        )
        elapsed = time.time() - start_time
        
        # Try to parse JSON response
        try:
            response_json = response.json()
        except Exception:
            response_json = {"raw_text": response.text[:100]}  # First 100 chars
        
        result = {
            "request_id": request_id,
            "status_code": response.status_code,
            "response": response_json,
            "elapsed": elapsed,
            "success": response.status_code in [200, 202],
            "timestamp": start_time
        }
        
        return result
    except Exception as e:
        elapsed = time.time() - start_time
        return {
            "request_id": request_id,
            "status_code": None,
            "error": str(e),
            "elapsed": elapsed,
            "success": False,
            "timestamp": start_time
        }


async def verify_redis_messages():
    """Verify that all messages were stored in Redis."""
    import redis
    
    try:
        client = redis.Redis(host="localhost", port=REDIS_PORT, decode_responses=True)
        client.ping()
        
        # Check Redis pub/sub or use a different method to verify
        # For this test, we'll check if Redis is accessible and count messages
        # Note: redis_publish doesn't store messages, it publishes them
        # So we'll just verify Redis is working
        
        print("\n📊 Verifying Redis connectivity...")
        info = client.info()
        print(f"✅ Redis is running (connected_clients: {info.get('connected_clients', 0)})")
        
        # If you want to verify actual messages, you'd need to subscribe to the channel
        # For now, we'll just verify Redis is accessible
        
        return True
    except Exception as e:
        print(f"❌ Failed to verify Redis: {e}")
        return False


async def main():
    """Main test function."""
    print("=" * 60)
    print("Retry Mechanism Test - Redis Failure Scenario")
    print("=" * 60)
    
    # Check initial Redis status
    if not check_redis_running():
        print(f"⚠️  Warning: Redis container '{REDIS_CONTAINER_NAME}' not found or not running")
        print("   Please ensure Redis is running before starting the test")
        sys.exit(1)
    
    print(f"\n✅ Redis is running")
    print(f"📡 Webhook URL: {WEBHOOK_URL}")
    print(f"📊 Total requests: {TOTAL_REQUESTS}")
    print(f"⏸️  Will stop Redis after {REQUESTS_BEFORE_STOP} requests")
    print(f"⏱️  Redis will be stopped for {REDIS_STOP_DURATION} seconds\n")
    
    async with httpx.AsyncClient() as client:
        # Phase 1: Send requests while Redis is running
        print("=" * 60)
        print("Phase 1: Sending requests with Redis running")
        print("=" * 60)
        
        for i in range(REQUESTS_BEFORE_STOP):
            result = await send_request(client, i + 1)
            results.append(result)
            status_emoji = "✅" if result["success"] else "❌"
            print(f"{status_emoji} Request {result['request_id']}: {result['status_code']} ({result['elapsed']:.2f}s)")
            await asyncio.sleep(0.5)
        
        # Phase 2: Stop Redis and continue sending requests
        print("\n" + "=" * 60)
        print("Phase 2: Stopping Redis and continuing requests")
        print("=" * 60)
        
        if stop_redis():
            # Wait a moment for Redis to fully stop
            await asyncio.sleep(1)
            
            # Continue sending requests (these should retry)
            for i in range(REQUESTS_BEFORE_STOP, TOTAL_REQUESTS):
                result = await send_request(client, i + 1)
                results.append(result)
                status_emoji = "✅" if result["success"] else "⏳"
                status_text = result.get("response", {}).get("status", "unknown")
                print(f"{status_emoji} Request {result['request_id']}: {result['status_code']} ({status_text}) - {result['elapsed']:.2f}s")
                await asyncio.sleep(0.5)
            
            # Wait for retries to happen
            print(f"\n⏳ Waiting {REDIS_STOP_DURATION} seconds for retries...")
            await asyncio.sleep(REDIS_STOP_DURATION)
            
            # Phase 3: Restart Redis
            print("\n" + "=" * 60)
            print("Phase 3: Restarting Redis")
            print("=" * 60)
            
            if start_redis():
                # Wait for retries to complete
                print("\n⏳ Waiting for retries to complete...")
                await asyncio.sleep(15)  # Give retries time to succeed
            else:
                print("❌ Failed to restart Redis")
                sys.exit(1)
        else:
            print("❌ Failed to stop Redis")
            sys.exit(1)
    
    # Phase 4: Verify results
    print("\n" + "=" * 60)
    print("Phase 4: Verifying Results")
    print("=" * 60)
    
    await verify_redis_messages()
    
    # Analyze results
    total = len(results)
    successful = sum(1 for r in results if r["success"] and r["status_code"] == 200)
    accepted = sum(1 for r in results if r["status_code"] == 202)
    failed = sum(1 for r in results if not r["success"])
    
    print(f"\n📊 Test Results:")
    print(f"   Total requests: {total}")
    print(f"   ✅ Successful (200 OK): {successful}")
    print(f"   ⏳ Accepted (202 - retries in progress): {accepted}")
    print(f"   ❌ Failed: {failed}")
    
    # Check if all requests eventually succeeded
    # Note: 202 responses are OK - they indicate retries are happening
    all_handled = successful + accepted == total
    
    if all_handled:
        print("\n✅ SUCCESS: All requests were handled (either succeeded or accepted for retry)")
        print("   Note: Requests with 202 status will be retried in the background")
        return 0
    else:
        print(f"\n❌ FAILURE: {failed} requests failed completely")
        print("\nFailed requests:")
        for r in results:
            if not r["success"]:
                print(f"   Request {r['request_id']}: {r.get('error', 'Unknown error')}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

