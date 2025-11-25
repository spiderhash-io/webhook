from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime

from src.webhook import WebhookHandler
from src.config import inject_connection_details, webhook_config_data, connection_config
from src.utils import EndpointStats
from src.rate_limiter import rate_limiter

app = FastAPI()
stats = EndpointStats()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)


async def cleanup_task():
    while True:
        now = datetime.utcnow()
        async with stats.lock:
            for endpoint in stats.timestamps:
                stats._cleanup_old_buckets(endpoint, now)
        print("Cleaning up old stats buckets")
        
        # Cleanup rate limiter
        await rate_limiter.cleanup_old_entries()
        print("Cleaning up old rate limiter entries")
        
        await asyncio.sleep(3600)  # Wait for 1 hour (3600 seconds) before next cleanup


@app.on_event("startup")
async def startup_event():
    global webhook_config_data
    webhook_config_data = await inject_connection_details(webhook_config_data, connection_config)
    print(webhook_config_data)

    asyncio.create_task(cleanup_task())


@app.post("/webhook/{webhook_id}")
async def read_webhook(webhook_id: str,  request: Request):

    try:
        webhook_handler = WebhookHandler(
            webhook_id,
            webhook_config_data,
            connection_config,
            request,
        )
    except HTTPException as e:
        raise e

    is_valid, message = await webhook_handler.validate_webhook()
    if not is_valid:
        raise HTTPException(status_code=401, detail=message)

    await webhook_handler.process_webhook()

    await stats.increment(webhook_id)

    return JSONResponse(content={"message": "200 OK"})


@app.get("/")
async def default_endpoint():
    return JSONResponse(content={"message": "200 OK"})


@app.get("/stats")
async def stats_endpoint():
    return stats.get_stats()



