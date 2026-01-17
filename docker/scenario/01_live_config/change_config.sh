#!/bin/bash
# Script to change webhook configuration in parallel with webhook sending
# This script modifies webhooks.json to test live config reload

set -e

CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)/config"
WEBHOOKS_FILE="${CONFIG_DIR}/webhooks.json"
DELAY=5  # Delay between config changes in seconds
CHANGE_COUNTER=1

echo "=========================================="
echo "Starting config changer"
echo "Config file: ${WEBHOOKS_FILE}"
echo "Delay between changes: ${DELAY}s"
echo "Press Ctrl+C to stop"
echo "=========================================="
echo ""

# Wait for config file to exist
echo "Waiting for config file..."
for i in {1..10}; do
    if [ -f "${WEBHOOKS_FILE}" ]; then
        echo "Config file found!"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "ERROR: Config file not found: ${WEBHOOKS_FILE}"
        exit 1
    fi
    sleep 1
done

echo ""
echo "Starting to change config..."
echo ""

# Change config multiple times
while true; do
    TIMESTAMP=$(date +%s)
    
    # Create different config variations
    case $((CHANGE_COUNTER % 4)) in
        0)
            # Original config
            NEW_CONFIG=$(cat <<EOF
{
    "test_webhook": {
        "data_type": "json",
        "module": "save_to_disk",
        "authorization": "Bearer test_token_123",
        "module-config": {
            "path": "/app/logs"
        }
    }
}
EOF
)
            CONFIG_NAME="original"
            ;;
        1)
            # Change path
            NEW_CONFIG=$(cat <<EOF
{
    "test_webhook": {
        "data_type": "json",
        "module": "save_to_disk",
        "authorization": "Bearer test_token_123",
        "module-config": {
            "path": "/app/logs/variant1"
        }
    }
}
EOF
)
            CONFIG_NAME="variant1 (path changed)"
            ;;
        2)
            # Change path to different location
            NEW_CONFIG=$(cat <<EOF
{
    "test_webhook": {
        "data_type": "json",
        "module": "save_to_disk",
        "authorization": "Bearer test_token_123",
        "module-config": {
            "path": "/app/logs/variant2"
        }
    }
}
EOF
)
            CONFIG_NAME="variant2 (path changed to variant2)"
            ;;
        3)
            # Add second webhook
            NEW_CONFIG=$(cat <<EOF
{
    "test_webhook": {
        "data_type": "json",
        "module": "save_to_disk",
        "authorization": "Bearer test_token_123",
        "module-config": {
            "path": "/app/logs"
        }
    },
    "test_webhook_2": {
        "data_type": "json",
        "module": "save_to_disk",
        "authorization": "Bearer test_token_123",
        "module-config": {
            "path": "/app/logs/secondary"
        }
    }
}
EOF
)
            CONFIG_NAME="variant3 (added second webhook)"
            ;;
    esac
    
    # Write new config
    echo "${NEW_CONFIG}" > "${WEBHOOKS_FILE}"
    
    echo "[Change ${CHANGE_COUNTER}] ✓ Config changed to: ${CONFIG_NAME} (timestamp: ${TIMESTAMP})"
    
    CHANGE_COUNTER=$((CHANGE_COUNTER + 1))
    sleep ${DELAY}
done

