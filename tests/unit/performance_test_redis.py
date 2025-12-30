import asyncio
import time
import httpx
from typing import List

# Configuration
WEBHOOK_URL = "http://localhost:8000/webhook/redis_publish_webhook"
TOTAL_REQUESTS = 5000
CONCURRENCY = 50

async def send_request(client: httpx.AsyncClient) -> float:
    start = time.time()
    try:
        response = await client.post(WEBHOOK_URL, json={"message": "test"})
        response.raise_for_status()
    except Exception as e:
        # For performance test we ignore failures
        pass
    return time.time() - start

async def worker(semaphore: asyncio.Semaphore, client: httpx.AsyncClient, results: List[float]):
    async with semaphore:
        latency = await send_request(client)
        results.append(latency)

async def run_test():
    semaphore = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient() as client:
        results: List[float] = []
        tasks = [worker(semaphore, client, results) for _ in range(TOTAL_REQUESTS)]
        start = time.time()
        await asyncio.gather(*tasks)
        total_time = time.time() - start
    avg_latency = sum(results) / len(results) if results else 0
    print(f"Total requests: {TOTAL_REQUESTS}")
    print(f"Concurrency: {CONCURRENCY}")
    print(f"Total time: {total_time:.2f}s")
    print(f"Average latency per request: {avg_latency:.4f}s")
    print(f"Requests per second: {TOTAL_REQUESTS / total_time:.2f}")

if __name__ == "__main__":
    asyncio.run(run_test())
