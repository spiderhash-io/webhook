# Live Config Reload Test Scenario

This scenario tests the live config reload functionality by running webhook instances that store webhooks to disk, sending continuous webhooks with numbered payloads, and changing configurations in parallel.

## Overview

The test scenario consists of:
1. **Docker Compose setup** - Runs webhook service with file watching enabled
2. **Webhook sender** - Continuously sends numbered webhook payloads
3. **Config changer** - Modifies webhook configuration in parallel
4. **Verification** - Checks that all payloads arrive at disk log path

## Prerequisites

- Docker and Docker Compose installed
- Bash shell
- curl command available

## Directory Structure

```
docker/scenario/
├── docker-compose.yaml      # Docker compose configuration
├── config/
│   ├── webhooks.json        # Webhook configuration (will be modified)
│   └── connections.json     # Connection configuration
├── logs/                    # Directory for webhook logs (created automatically)
├── send_webhooks.sh         # Script to send continuous webhooks
├── change_config.sh         # Script to change config in parallel
├── verify_results.sh        # Script to verify results
└── README.md               # This file
```

## Usage

### 1. Start the webhook service

```bash
cd docker/scenario
docker-compose up -d
```

Wait for the service to be ready (check logs with `docker-compose logs -f`).

### 2. Run webhook sender (in one terminal)

```bash
cd docker/scenario
./send_webhooks.sh
```

This will continuously send webhooks with numbered payloads.

### 3. Run config changer (in another terminal)

```bash
cd docker/scenario
./change_config.sh
```

This will modify the webhook configuration every 5 seconds, cycling through different variants.

### 4. Let it run

Let both scripts run for a period of time (e.g., 1-2 minutes) to test the live reload functionality.

### 5. Stop the scripts

Press `Ctrl+C` in both terminal windows to stop the scripts.

### 6. Verify results

```bash
cd docker/scenario
./verify_results.sh
```

This will show how many webhook files were created and list them.

### 7. Cleanup

```bash
cd docker/scenario
docker-compose down
rm -rf logs/*
```

## Expected Behavior

- Webhooks should continue to be processed even when config changes
- All webhook payloads should be saved to disk in the `/app/logs` directory (mapped to `./logs` on host)
- Config changes should be picked up automatically (with debounce delay)
- No webhooks should be lost during config reload

## Configuration Details

### Environment Variables

- `CONFIG_FILE_WATCHING_ENABLED=true` - Enables automatic file watching
- `CONFIG_RELOAD_DEBOUNCE_SECONDS=2.0` - Debounce delay for config reloads
- `CONFIG_RELOAD_ADMIN_TOKEN=test_admin_token_123` - Admin token for manual reload API

### Webhook Configuration

The initial webhook configuration saves payloads to `/app/logs` directory. The config changer will modify:
- Save path
- Filename pattern
- Add/remove webhook entries

## Troubleshooting

### Webhook service not starting

Check logs:
```bash
docker-compose logs webhook
```

### Webhooks not being received

1. Check if service is healthy:
```bash
curl http://localhost:8000/
```

2. Check webhook endpoint:
```bash
curl -X POST http://localhost:8000/webhook/test_webhook \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test_token_123" \
  -d '{"test": "data"}'
```

### Config changes not being picked up

1. Check if file watching is enabled in logs
2. Verify config file is writable
3. Check debounce delay setting
4. Manually trigger reload:
```bash
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer test_admin_token_123" \
  -H "Content-Type: application/json" \
  -d '{"reload_webhooks": true}'
```

## Notes

- The webhook sender sends webhooks every 100ms (0.1 seconds)
- The config changer modifies config every 5 seconds
- Config changes are debounced (2 seconds delay) before being applied
- All webhook files are saved in the `logs/` directory
- The scenario tests that webhooks continue processing during config reloads


