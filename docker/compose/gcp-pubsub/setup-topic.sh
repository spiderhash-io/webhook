#!/bin/bash
# Setup script to create GCP Pub/Sub topic in the emulator

set -e

PROJECT_ID="test-project"
TOPIC_NAME="webhook-events"
EMULATOR_HOST="pubsub-emulator:8085"

echo "Creating GCP Pub/Sub topic: projects/${PROJECT_ID}/topics/${TOPIC_NAME}"

# Wait for emulator to be ready
for i in {1..30}; do
    if curl -s -f "http://${EMULATOR_HOST}" > /dev/null 2>&1; then
        echo "Pub/Sub emulator is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: Pub/Sub emulator did not become ready"
        exit 1
    fi
    sleep 1
done

# Create topic using gcloud (inside the emulator container)
docker compose exec -T pubsub-emulator gcloud pubsub topics create "${TOPIC_NAME}" \
    --project="${PROJECT_ID}" \
    --emulator-host="localhost:8085" 2>&1 || {
    # Topic might already exist, which is OK
    if [ $? -eq 1 ]; then
        echo "Topic might already exist, continuing..."
    fi
}

echo "Topic setup complete!"

