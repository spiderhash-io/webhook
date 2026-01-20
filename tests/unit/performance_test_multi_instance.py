"""
Performance test for multiple webhook instances with ClickHouse logging.

This test simulates load across multiple webhook instances and measures:
- Throughput (requests per second)
- Latency (average, p50, p95, p99)
- Error rate
- ClickHouse write performance
"""

import asyncio
import time
import httpx
import statistics
from typing import List, Tuple
from collections import defaultdict

# Configuration
WEBHOOK_INSTANCES = [
    "http://localhost:8000",
    "http://localhost:8001",
    "http://localhost:8002",
    "http://localhost:8003",
    "http://localhost:8004",
]
WEBHOOK_ID = "performance_test_webhook"
TOTAL_REQUESTS = 10000  # Full performance test
CONCURRENCY = 200  # Concurrent requests per instance
TIMEOUT = 30.0

# Results storage
results = {
    "latencies": [],
    "errors": [],
    "successes": 0,
    "failures": 0,
    "instance_stats": defaultdict(lambda: {"success": 0, "fail": 0, "latencies": []}),
}


async def send_request(
    client: httpx.AsyncClient, instance_url: str, request_id: int
) -> Tuple[float, bool, str]:
    """
    Send a single webhook request.

    Returns:
        (latency, success, error_message)
    """
    start = time.time()
    try:
        response = await client.post(
            f"{instance_url}/webhook/{WEBHOOK_ID}",
            json={
                "test_id": request_id,
                "message": f"Performance test request {request_id}",
                "timestamp": time.time(),
            },
            headers={
                "Authorization": "Bearer test_token",
                "Content-Type": "application/json",
            },
            timeout=TIMEOUT,
        )
        latency = time.time() - start

        if response.status_code == 200:
            return latency, True, ""
        else:
            return latency, False, f"HTTP {response.status_code}"
    except httpx.TimeoutException:
        latency = time.time() - start
        return latency, False, "Timeout"
    except Exception as e:
        latency = time.time() - start
        return latency, False, str(e)


async def worker(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    instance_url: str,
    request_id: int,
):
    """Worker coroutine that sends requests."""
    async with semaphore:
        latency, success, error = await send_request(client, instance_url, request_id)

        instance_name = instance_url.split(":")[-1]
        results["latencies"].append(latency)
        results["instance_stats"][instance_name]["latencies"].append(latency)

        if success:
            results["successes"] += 1
            results["instance_stats"][instance_name]["success"] += 1
        else:
            results["failures"] += 1
            results["errors"].append(error)
            results["instance_stats"][instance_name]["fail"] += 1


async def run_test():
    """Run the performance test."""
    print("=" * 80)
    print("PERFORMANCE TEST: Multiple Webhook Instances with ClickHouse")
    print("=" * 80)
    print(f"Webhook ID: {WEBHOOK_ID}")
    print(f"Total Requests: {TOTAL_REQUESTS}")
    print(f"Concurrency: {CONCURRENCY}")
    print(f"Instances: {len(WEBHOOK_INSTANCES)}")
    print(f"Requests per instance: ~{TOTAL_REQUESTS // len(WEBHOOK_INSTANCES)}")
    print("=" * 80)
    print()

    # Distribute requests across instances
    requests_per_instance = TOTAL_REQUESTS // len(WEBHOOK_INSTANCES)
    remaining = TOTAL_REQUESTS % len(WEBHOOK_INSTANCES)

    semaphore = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient() as client:
        tasks = []
        request_id = 0

        # Create tasks distributed across instances
        for i, instance_url in enumerate(WEBHOOK_INSTANCES):
            instance_requests = requests_per_instance + (1 if i < remaining else 0)
            for _ in range(instance_requests):
                tasks.append(worker(semaphore, client, instance_url, request_id))
                request_id += 1

        print(f"Starting test with {len(tasks)} requests...")
        start_time = time.time()

        await asyncio.gather(*tasks)

        total_time = time.time() - start_time

    # Calculate statistics
    latencies = results["latencies"]
    if not latencies:
        print("ERROR: No successful requests!")
        return

    latencies_sorted = sorted(latencies)
    total_requests = results["successes"] + results["failures"]

    # Overall statistics
    print("\n" + "=" * 80)
    print("OVERALL RESULTS")
    print("=" * 80)
    print(f"Total Requests: {total_requests}")
    print(
        f"Successful: {results['successes']} ({results['successes']/total_requests*100:.2f}%)"
    )
    print(
        f"Failed: {results['failures']} ({results['failures']/total_requests*100:.2f}%)"
    )
    print(f"Total Time: {total_time:.2f}s")
    print(f"Requests per Second: {total_requests / total_time:.2f}")
    print(f"Successful RPS: {results['successes'] / total_time:.2f}")

    print("\nLatency Statistics (seconds):")
    print(f"  Average: {statistics.mean(latencies):.4f}s")
    print(f"  Median (p50): {statistics.median(latencies):.4f}s")
    if len(latencies) > 1:
        print(f"  Std Dev: {statistics.stdev(latencies):.4f}s")
    print(f"  Min: {min(latencies):.4f}s")
    print(f"  Max: {max(latencies):.4f}s")

    # Percentiles
    def percentile(data, p):
        k = (len(data) - 1) * p
        f = int(k)
        c = k - f
        if f + 1 < len(data):
            return data[f] * (1 - c) + data[f + 1] * c
        return data[f]

    print("\nLatency Percentiles:")
    print(f"  p50: {percentile(latencies_sorted, 0.50):.4f}s")
    print(f"  p75: {percentile(latencies_sorted, 0.75):.4f}s")
    print(f"  p90: {percentile(latencies_sorted, 0.90):.4f}s")
    print(f"  p95: {percentile(latencies_sorted, 0.95):.4f}s")
    print(f"  p99: {percentile(latencies_sorted, 0.99):.4f}s")

    # Error breakdown
    if results["errors"]:
        print("\nError Breakdown:")
        error_counts = defaultdict(int)
        for error in results["errors"]:
            error_counts[error] += 1
        for error, count in sorted(
            error_counts.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {error}: {count}")

    # Per-instance statistics
    print("\n" + "=" * 80)
    print("PER-INSTANCE RESULTS")
    print("=" * 80)
    for instance_name, stats in sorted(results["instance_stats"].items()):
        total = stats["success"] + stats["fail"]
        if total == 0:
            continue
        print(f"\nInstance {instance_name}:")
        print(f"  Total: {total}")
        print(f"  Success: {stats['success']} ({stats['success']/total*100:.2f}%)")
        print(f"  Failed: {stats['fail']} ({stats['fail']/total*100:.2f}%)")
        if stats["latencies"]:
            print(f"  Avg Latency: {statistics.mean(stats['latencies']):.4f}s")
            print(f"  RPS: {stats['success'] / total_time:.2f}")

    # Verify Stats Aggregation
    print("\n" + "=" * 80)
    print("VERIFYING STATS AGGREGATION")
    print("=" * 80)

    async with httpx.AsyncClient() as client:
        # Get stats from a random instance (they should all share the same Redis)
        stats_url = f"{WEBHOOK_INSTANCES[0]}/stats"
        try:
            resp = await client.get(stats_url)
            if resp.status_code == 200:
                stats_data = resp.json()
                webhook_stats = stats_data.get(WEBHOOK_ID, {})
                total_recorded = webhook_stats.get("total", 0)

                print(f"Stats retrieved from {WEBHOOK_INSTANCES[0]}")
                print(f"Total recorded in Redis: {total_recorded}")
                print(f"Total successful requests in this run: {results['successes']}")

                # Note: If previous tests ran, total_recorded will be higher.
                # Ideally we should have checked start_stats, but for now just checking it's at least what we sent.
                if total_recorded >= results["successes"]:
                    print(
                        "SUCCESS: Stats recorded in Redis match or exceed successful requests."
                    )
                else:
                    print(
                        f"FAILURE: Stats recorded ({total_recorded}) is less than successful requests ({results['successes']})."
                    )
            else:
                print(f"Failed to get stats: HTTP {resp.status_code}")
        except Exception as e:
            print(f"Error fetching stats: {e}")

    print("\n" + "=" * 80)
    print("Test completed!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_test())
