# Configuration Files

This directory contains configuration files organized by environment.

## Directory Structure

- **`examples/`** - Example configuration files for reference
  - `webhooks.example.json` - Example webhook configurations
  - `connections.example.json` - Example connection configurations
  - `webhooks.performance.json` - Performance testing webhook configurations

- **`development/`** - Development environment configurations
  - `webhooks.json` - Active webhook configurations for development
  - `connections.json` - Active connection configurations for development
  - `connections.docker.json` - Docker-specific connection configurations

- **`production/`** - Production environment configurations (gitignored)
  - `webhooks.json` - Production webhook configurations
  - `connections.json` - Production connection configurations

## Usage

### Development
Copy example files to development directory:
```bash
cp config/examples/webhooks.example.json config/development/webhooks.json
cp config/examples/connections.example.json config/development/connections.json
```

### Production
Create production-specific configurations in `config/production/` directory. These files are gitignored for security.

### Docker
Docker compose files reference configurations from `config/development/` by default. Update the volume mounts in compose files to use different configurations if needed.

## Environment Variables

Configuration files support environment variable substitution using `{$VAR}` syntax:
- `{$VAR}` - Replace with environment variable value
- `{$VAR:default}` - Use environment variable or default value if not set

Example:
```json
{
  "redis_conn": {
    "type": "redis-rq",
    "host": "{$REDIS_HOST:localhost}",
    "port": "{$REDIS_PORT:6379}"
  }
}
```

