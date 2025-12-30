"""
Performance test for single webhook instance.

This test measures:
- Throughput (requests per second)
- Latency (average, p50, p95, p99)
- Error rate
"""
import asyncio
import time
import httpx
import statistics
from typing import List, Tuple
from collections import defaultdict

# Configuration
WEBHOOK_URL = "http://localhost:8000"
WEBHOOK_ID = "performance_test_webhook"
TOTAL_REQUESTS = 5000  # Adjustable
CONCURRENCY = 100  # Concurrent requests
TIMEOUT = 30.0

# Results storage
results = {
    'latencies': [],
    'errors': [],
    'successes': 0,
    'failures': 0,
    'status_codes': defaultdict(int)
}


async def send_request(
    client: httpx.AsyncClient,
    request_id: int
) -> Tuple[float, bool, str, int]:
    """
    Send a single webhook request.
    
    Returns:
        (latency, success, error_message, status_code)
    """
    start = time.time()
    try:
        response = await client.post(
            f"{WEBHOOK_URL}/webhook/{WEBHOOK_ID}",
            json={
                "test_id": request_id,
                "message": f"Performance test request {request_id}",
                "timestamp": time.time()
            },
            headers={
                "Authorization": "Bearer test_token",
                "Content-Type": "application/json"
            },
            timeout=TIMEOUT
        )
        latency = time.time() - start
        
        status_code = response.status_code
        results['status_codes'][status_code] += 1
        
        if status_code in [200, 202]:  # 200 OK or 202 Accepted (retries)
            return latency, True, "", status_code
        else:
            return latency, False, f"HTTP {status_code}", status_code
    except httpx.TimeoutException:
        latency = time.time() - start
        return latency, False, "Timeout", 0
    except Exception as e:
        latency = time.time() - start
        return latency, False, str(e), 0


async def worker(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    request_id: int
):
    """Worker coroutine that sends requests."""
    async with semaphore:
        latency, success, error, status_code = await send_request(client, request_id)
        
        results['latencies'].append(latency)
        
        if success:
            results['successes'] += 1
        else:
            results['failures'] += 1
            results['errors'].append(error)


async def run_test():
    """Run the performance test."""
    print("=" * 80)
    print("PERFORMANCE TEST: Single Webhook Instance")
    print("=" * 80)
    print(f"Webhook URL: {WEBHOOK_URL}")
    print(f"Webhook ID: {WEBHOOK_ID}")
    print(f"Total Requests: {TOTAL_REQUESTS}")
    print(f"Concurrency: {CONCURRENCY}")
    print("=" * 80)
    print()
    
    semaphore = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient() as client:
        tasks = []
        
        # Create tasks
        for request_id in range(TOTAL_REQUESTS):
            tasks.append(worker(semaphore, client, request_id))
        
        print(f"Starting test with {len(tasks)} requests...")
        start_time = time.time()
        
        await asyncio.gather(*tasks)
        
        total_time = time.time() - start_time
    
    # Calculate statistics
    latencies = results['latencies']
    if not latencies:
        print("ERROR: No successful requests!")
        return
    
    latencies_sorted = sorted(latencies)
    total_requests = results['successes'] + results['failures']
    
    # Overall statistics
    print("\n" + "=" * 80)
    print("OVERALL RESULTS")
    print("=" * 80)
    print(f"Total Requests: {total_requests}")
    print(f"Successful: {results['successes']} ({results['successes']/total_requests*100:.2f}%)")
    print(f"Failed: {results['failures']} ({results['failures']/total_requests*100:.2f}%)")
    print(f"Total Time: {total_time:.2f}s")
    print(f"Requests per Second: {total_requests / total_time:.2f}")
    print(f"Successful RPS: {results['successes'] / total_time:.2f}")
    print()
    
    if latencies:
        print("Latency Statistics (seconds):")
        print(f"  Average: {statistics.mean(latencies):.4f}s")
        print(f"  Median (p50): {statistics.median(latencies):.4f}s")
        if len(latencies) > 1:
            print(f"  Std Dev: {statistics.stdev(latencies):.4f}s")
        print(f"  Min: {min(latencies):.4f}s")
        print(f"  Max: {max(latencies):.4f}s")
        print()
        
        print("Latency Percentiles:")
        print(f"  p50: {latencies_sorted[int(len(latencies_sorted) * 0.50)]:.4f}s")
        print(f"  p75: {latencies_sorted[int(len(latencies_sorted) * 0.75)]:.4f}s")
        print(f"  p90: {latencies_sorted[int(len(latencies_sorted) * 0.90)]:.4f}s")
        print(f"  p95: {latencies_sorted[int(len(latencies_sorted) * 0.95)]:.4f}s")
        print(f"  p99: {latencies_sorted[int(len(latencies_sorted) * 0.99)]:.4f}s")
        print()
    
    # Status code breakdown
    if results['status_codes']:
        print("Status Code Breakdown:")
        for code, count in sorted(results['status_codes'].items()):
            print(f"  {code}: {count} ({count/total_requests*100:.2f}%)")
        print()
    
    # Error breakdown
    if results['errors']:
        error_counts = defaultdict(int)
        for error in results['errors']:
            error_counts[error] += 1
        
        print("Error Breakdown:")
        for error, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {error}: {count}")
        print()
    
    print("=" * 80)
    print("Test completed!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_test())

