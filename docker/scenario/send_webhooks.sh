#!/bin/bash
# Script to send nonstop webhooks with numbered payloads
# This script sends webhooks continuously to test live config reload
# Runs from inside the container for reliable HTTP requests

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

TOKEN="test_token_123"
WEBHOOK_ID="test_webhook"
DELAY=0.1  # Delay between webhooks in seconds (100ms)
COUNTER=1

echo "=========================================="
echo "Starting webhook sender"
echo "Sending webhooks to: http://localhost:8000/webhook/${WEBHOOK_ID}"
echo "Delay between webhooks: ${DELAY}s"
echo "Press Ctrl+C to stop"
echo "=========================================="
echo ""

# Wait for webhook service to be ready
echo "Waiting for webhook service..."
for i in {1..30}; do
    if docker compose exec -T webhook python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" > /dev/null 2>&1; then
        echo "Webhook service is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: Webhook service did not become ready"
        exit 1
    fi
    sleep 1
done

echo ""
echo "Starting to send webhooks..."
echo ""

# Send webhooks continuously using Python from inside container
docker compose exec -T webhook python3 << 'PYTHON_SCRIPT'
import requests
import time
import sys
import json
from datetime import datetime

WEBHOOK_URL = "http://localhost:8000"
TOKEN = "test_token_123"
WEBHOOK_ID = "test_webhook"
DELAY = 0.1
counter = 1

try:
    while True:
        timestamp = datetime.now().isoformat()
        payload = {
            "webhook_number": counter,
            "timestamp": timestamp,
            "message": f"Webhook payload number {counter}",
            "test_data": {
                "counter": counter,
                "sequence": counter,
                "source": "live_reload_test"
            }
        }
        
        try:
            response = requests.post(
                f"{WEBHOOK_URL}/webhook/{WEBHOOK_ID}",
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {TOKEN}"
                },
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"[{counter}] ✓ Webhook sent successfully (HTTP {response.status_code})")
            else:
                print(f"[{counter}] ✗ Webhook failed (HTTP {response.status_code}): {response.text}")
        except Exception as e:
            print(f"[{counter}] ✗ Webhook failed with error: {e}")
        
        counter += 1
        time.sleep(DELAY)
except KeyboardInterrupt:
    print("\nStopping webhook sender...")
    sys.exit(0)
PYTHON_SCRIPT

