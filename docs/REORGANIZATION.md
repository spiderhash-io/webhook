# Project Reorganization Summary

This document summarizes the folder structure reorganization completed on December 30, 2024.

## Changes Made

### 1. Tests Reorganization
- **Before**: Unit tests were in `src/tests/`, integration tests in `tests/integration/`
- **After**: 
  - Unit tests moved to `tests/unit/`
  - Integration tests remain in `tests/integration/`
  - Both are now under the same `tests/` parent directory

### 2. Configuration Files Organization
- **Before**: Config files scattered in root directory
- **After**: Organized into `config/` directory:
  - `config/examples/` - Example configurations (webhooks.example.json, connections.example.json, webhooks.performance.json)
  - `config/development/` - Development configurations (webhooks.json, connections.json, connections.docker.json)
  - `config/production/` - Production configurations (gitignored, for production use)

### 3. Docker Files Organization
- **Before**: Dockerfiles and docker-compose.yaml in root directory
- **After**: Organized into `docker/` directory:
  - `docker/Dockerfile`, `docker/Dockerfile.small`, `docker/Dockerfile.smaller` - Dockerfiles
  - `docker/compose/docker-compose.yaml` - Main multi-instance compose file
  - `docker/compose/webhook-only/` - Single webhook instance
  - `docker/compose/redis/` - Redis testing
  - `docker/compose/rabbitmq/` - RabbitMQ testing
  - `docker/compose/clickhouse/` - ClickHouse testing
  - `docker/compose/kafka/` - Kafka testing
  - `docker/compose/postgres/` - PostgreSQL testing
  - `docker/compose/full-stack/` - All services together

### 4. Scripts Organization
- **Before**: Scripts in `src/tests/`
- **After**: Moved to `scripts/` directory:
  - `scripts/run_performance_test.sh` - Performance test runner

## Updated Files

### Configuration Files
- `pytest.ini` - Updated testpaths to `tests`
- `Makefile` - Updated docker-compose paths and test paths
- `docker/compose/docker-compose.yaml` - Updated build context and volume mounts
- `scripts/run_performance_test.sh` - Updated paths for new structure

## New Structure

```
core-webhook-module/
├── src/                    # Core product code (unchanged)
├── tests/                  # All tests
│   ├── unit/              # Unit tests (moved from src/tests/)
│   └── integration/       # Integration tests (existing)
├── config/                 # Configuration files
│   ├── examples/          # Example configs
│   ├── development/       # Dev configs
│   └── production/        # Production configs (gitignored)
├── docker/                 # Docker files
│   ├── Dockerfile*        # Dockerfiles
│   └── compose/           # Docker compose files
│       ├── docker-compose.yaml  # Main multi-instance
│       ├── webhook-only/   # Single instance
│       ├── redis/          # Redis testing
│       ├── rabbitmq/       # RabbitMQ testing
│       ├── clickhouse/     # ClickHouse testing
│       ├── kafka/          # Kafka testing
│       ├── postgres/       # PostgreSQL testing
│       └── full-stack/     # All services
├── scripts/                # Utility scripts
├── docs/                   # Documentation (unchanged)
├── docusaurus/            # Documentation site (unchanged)
└── [root files]           # README.md, Makefile, requirements.txt, etc.
```

## Usage After Reorganization

### Running Tests
```bash
# Unit tests
make test
pytest tests/unit/

# Integration tests
make integration-up
make test-integration
pytest tests/integration/
```

### Using Docker Compose
```bash
# Main multi-instance setup
docker-compose -f docker/compose/docker-compose.yaml up -d

# Individual services
docker-compose -f docker/compose/redis/docker-compose.yaml up -d
docker-compose -f docker/compose/rabbitmq/docker-compose.yaml up -d
# etc.
```

### Configuration Files
- Development configs: `config/development/`
- Example configs: `config/examples/`
- Production configs: `config/production/` (create as needed)

## Migration Notes

- All unit tests have been moved from `src/tests/` to `tests/unit/`
- Config files have been moved to `config/` subdirectories
- Docker files have been moved to `docker/` directory
- All path references have been updated in configuration files
- The `src/tests/` directory has been removed (empty after migration)

## Benefits

1. **Cleaner root directory** - Only essential files remain in root
2. **Better organization** - Related files grouped together
3. **Easier testing** - Unit and integration tests clearly separated
4. **Modular Docker setup** - Individual services can be tested independently
5. **Clear configuration management** - Configs organized by environment

