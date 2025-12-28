# Code Coverage Gaps Report

**Current Coverage: 89%**  
**Target: 100%**

This report identifies what needs to be tested to achieve 100% code coverage.

---

## Files with Lowest Coverage (Priority Order)

### 1. `src/main.py` - 57% coverage (182 missing statements)

**Missing Coverage Areas:**

#### Startup Event Handler (`startup_event()`)
- [ ] ConfigManager initialization success path with details
- [ ] ConfigManager initialization failure path (exception handling)
- [ ] Legacy config loading fallback path
- [ ] Connection validation with ConfigManager
- [ ] Connection validation with legacy config
- [ ] Connection validation exception handling
- [ ] ClickHouse logger initialization with ConfigManager
- [ ] ClickHouse logger initialization with legacy config
- [ ] ClickHouse logger connection failure handling
- [ ] ClickHouse logger unavailable path
- [ ] Config file watcher startup (file_watching_enabled=True)
- [ ] Config file watcher debounce validation (too small, too large, invalid)
- [ ] Config file watcher startup exception handling
- [ ] Background cleanup task creation

#### Shutdown Event Handler (`shutdown_event()`)
- [ ] ConfigFileWatcher.stop() exception handling
- [ ] ConnectionPoolRegistry.close_all_pools() exception handling
- [ ] ClickHouseAnalytics.disconnect() exception handling
- [ ] RedisEndpointStats.close() exception handling

#### Connection Validation (`validate_connections()`)
- [ ] PostgreSQL connection validation (success, failure, timeout)
- [ ] MySQL connection validation (success, failure, timeout)
- [ ] Kafka connection validation (success, failure, timeout)
- [ ] Redis-RQ connection validation (success, failure, timeout)
- [ ] RabbitMQ connection validation (success, failure, timeout)
- [ ] ClickHouse connection validation (success, failure, timeout)
- [ ] Unknown connection type handling
- [ ] Connection timeout handling
- [ ] Connection error sanitization
- [ ] SSRF prevention in connection validation

#### Webhook Endpoint (`read_webhook()`)
- [ ] WebhookHandler initialization with ConfigManager
- [ ] WebhookHandler initialization with legacy config
- [ ] WebhookHandler initialization exception handling
- [ ] Task result handling (success, failure, exception)
- [ ] Retry configuration with task handling
- [ ] ClickHouse logging with task manager
- [ ] ClickHouse logging exception handling

#### Default Endpoint (`default_endpoint()`)
- [ ] Rate limiting enforcement
- [ ] Rate limit exceeded response
- [ ] IP extraction from X-Forwarded-For
- [ ] IP extraction from request.client.host

#### Stats Endpoint (`stats_endpoint()`)
- [ ] Authentication token validation (Bearer format, direct token)
- [ ] IP whitelist validation
- [ ] Rate limiting enforcement
- [ ] Stats sanitization (STATS_SANITIZE_IDS enabled)
- [ ] Stats retrieval

#### Admin Endpoints
- [ ] `/admin/reload-config` - All error paths
- [ ] `/admin/config-status` - All error paths

#### Custom OpenAPI (`custom_openapi()`)
- [ ] OpenAPI schema generation with ConfigManager
- [ ] OpenAPI schema generation with legacy config
- [ ] OpenAPI schema generation exception handling
- [ ] Fallback to default OpenAPI

#### CORS Configuration
- [ ] CORS origin validation (wildcard rejection, invalid formats)
- [ ] CORS origin parsing and filtering
- [ ] CORS credentials configuration

#### Security Headers Middleware (`SecurityHeadersMiddleware`)
- [ ] HSTS header generation (HTTPS detection)
- [ ] HSTS configuration validation (max_age, includeSubDomains, preload)
- [ ] CSP policy generation (docs endpoint vs default)
- [ ] Custom CSP policy from environment variable

#### Cleanup Task (`cleanup_task()`)
- [ ] Rate limiter cleanup execution
- [ ] Cleanup task loop

---

### 2. `src/analytics_processor.py` - 58% coverage (62 missing statements)

**Missing Coverage Areas:**
- [ ] `AnalyticsProcessor.__init__()` with various configs
- [ ] `AnalyticsProcessor.connect()` - connection success/failure
- [ ] `AnalyticsProcessor.disconnect()` - all paths
- [ ] `AnalyticsProcessor.process_events()` - main processing loop
- [ ] `AnalyticsProcessor.get_all_webhook_ids()` - with/without data
- [ ] `AnalyticsProcessor.calculate_stats()` - all calculation paths
- [ ] `ClickHouseAnalytics.__init__()` in analytics processor context
- [ ] Error handling in all methods
- [ ] Webhook ID validation in analytics processor
- [ ] SSRF prevention in connection host validation

---

### 3. `src/modules/s3.py` - 58% coverage (49 missing statements)

**Missing Coverage Areas:**
- [ ] `S3Module.__init__()` - various config scenarios
- [ ] `S3Module.setup()` - S3 client initialization
- [ ] `S3Module.setup()` - exception handling
- [ ] `S3Module.process()` - upload success path
- [ ] `S3Module.process()` - upload failure handling
- [ ] `S3Module.process()` - filename pattern generation
- [ ] `S3Module.process()` - prefix handling
- [ ] `S3Module.process()` - ContentType handling
- [ ] `S3Module.process()` - Metadata handling
- [ ] `S3Module.teardown()` - client cleanup
- [ ] Error handling for boto3 exceptions
- [ ] Path validation edge cases

---

### 4. `src/clickhouse_analytics.py` - 62% coverage (74 missing statements)

**Missing Coverage Areas:**
- [ ] `ClickHouseAnalytics.__init__()` - various configs
- [ ] `ClickHouseAnalytics.connect()` - connection success
- [ ] `ClickHouseAnalytics.connect()` - connection failure
- [ ] `ClickHouseAnalytics.connect()` - SSRF validation
- [ ] `ClickHouseAnalytics.disconnect()` - all paths
- [ ] `ClickHouseAnalytics.save_log()` - successful save
- [ ] `ClickHouseAnalytics.save_log()` - error handling
- [ ] `ClickHouseAnalytics.save_stats()` - successful save
- [ ] `ClickHouseAnalytics.save_stats()` - error handling
- [ ] `ClickHouseAnalytics._ensure_tables()` - table creation
- [ ] `ClickHouseAnalytics._ensure_tables()` - table already exists
- [ ] `ClickHouseAnalytics._ensure_tables()` - error handling
- [ ] Webhook ID validation in save methods
- [ ] Payload serialization edge cases

---

### 5. `src/modules/mysql.py` - 66% coverage (114 missing statements)

**Missing Coverage Areas:**
- [ ] `MySQLModule.__init__()` - all storage modes (JSON, relational, hybrid)
- [ ] `MySQLModule.setup()` - connection pool creation
- [ ] `MySQLModule.setup()` - exception handling
- [ ] `MySQLModule.process()` - JSON mode
- [ ] `MySQLModule.process()` - Relational mode
- [ ] `MySQLModule.process()` - Hybrid mode
- [ ] `MySQLModule.process()` - Upsert operations
- [ ] `MySQLModule.process()` - Table creation
- [ ] `MySQLModule.process()` - Index creation
- [ ] `MySQLModule.process()` - Error handling
- [ ] `MySQLModule._validate_table_name()` - all validation paths
- [ ] `MySQLModule._validate_index_name()` - all validation paths
- [ ] `MySQLModule._validate_upsert_key()` - all validation paths
- [ ] `MySQLModule._validate_field_name()` - all validation paths
- [ ] `MySQLModule._create_table_if_not_exists()` - all paths
- [ ] `MySQLModule._create_index_if_not_exists()` - all paths
- [ ] `MySQLModule._insert_or_update()` - all paths
- [ ] `MySQLModule.teardown()` - pool cleanup

---

### 6. `src/modules/postgres.py` - 69% coverage (96 missing statements)

**Missing Coverage Areas:**
- [ ] `PostgreSQLModule.__init__()` - all storage modes
- [ ] `PostgreSQLModule.setup()` - connection pool creation
- [ ] `PostgreSQLModule.setup()` - exception handling
- [ ] `PostgreSQLModule.process()` - JSON mode
- [ ] `PostgreSQLModule.process()` - Relational mode
- [ ] `PostgreSQLModule.process()` - Hybrid mode
- [ ] `PostgreSQLModule.process()` - Upsert operations
- [ ] `PostgreSQLModule.process()` - Table creation
- [ ] `PostgreSQLModule.process()` - Index creation
- [ ] `PostgreSQLModule.process()` - Error handling
- [ ] `PostgreSQLModule._validate_table_name()` - all paths
- [ ] `PostgreSQLModule._validate_index_name()` - all paths
- [ ] `PostgreSQLModule._validate_upsert_key()` - all paths
- [ ] `PostgreSQLModule._validate_field_name()` - all paths
- [ ] `PostgreSQLModule._create_table_if_not_exists()` - all paths
- [ ] `PostgreSQLModule._create_index_if_not_exists()` - all paths
- [ ] `PostgreSQLModule._insert_or_update()` - all paths
- [ ] `PostgreSQLModule.teardown()` - pool cleanup

---

### 7. `src/config_manager.py` - 68% coverage (65 missing statements)

**Missing Coverage Areas:**
- [ ] `ConfigManager.__init__()` - all initialization paths
- [ ] `ConfigManager.initialize()` - success path
- [ ] `ConfigManager.initialize()` - failure paths
- [ ] `ConfigManager.reload_webhooks()` - all paths
- [ ] `ConfigManager.reload_connections()` - all paths
- [ ] `ConfigManager.reload_all()` - all paths
- [ ] `ConfigManager.get_webhook_config()` - found/not found
- [ ] `ConfigManager.get_all_webhook_configs()` - all paths
- [ ] `ConfigManager.get_all_connection_configs()` - all paths
- [ ] `ConfigManager.get_status()` - all status paths
- [ ] `ConfigManager._validate_webhook_config()` - all validation paths
- [ ] `ConfigManager._validate_connection_config()` - all validation paths
- [ ] Error handling in all methods

---

### 8. `src/utils.py` - 81% coverage (88 missing statements)

**Missing Coverage Areas:**
- [ ] `_sanitize_context()` - all sanitization paths (NEW FUNCTION)
- [ ] `save_to_disk()` - legacy function (may be unused)
- [ ] `print_to_stdout()` - legacy function (may be unused)
- [ ] `EndpointStats._cleanup_old_buckets()` - cleanup logic
- [ ] `EndpointStats.get_stats()` - all return paths
- [ ] `RedisEndpointStats._reconnect_if_needed()` - reconnection logic
- [ ] `RedisEndpointStats._get_stats_optimized()` - optimized path
- [ ] `RedisEndpointStats.increment_multi_resolution()` - all resolution paths
- [ ] `RedisEndpointStats._cleanup_old_buckets()` - cleanup logic
- [ ] `CredentialCleaner._clean_dict_recursive()` - all recursion paths
- [ ] `CredentialCleaner.clean_headers()` - all header cleaning paths
- [ ] `CredentialCleaner.clean_query_params()` - all query param paths
- [ ] `load_env_vars()` - all recursion and edge cases
- [ ] `_sanitize_env_value()` - all sanitization paths

---

### 9. `src/validators.py` - 91% coverage (74 missing statements)

**Missing Coverage Areas:**
- [ ] `OAuth1NonceTracker.check_and_store_nonce()` - all nonce tracking paths
- [ ] `OAuth1NonceTracker._cleanup_expired_nonces()` - cleanup logic
- [ ] `OAuth1NonceTracker.get_stats()` - stats retrieval
- [ ] `OAuth1NonceTracker.clear()` - clearing logic
- [ ] `OAuth1Validator._build_signature_base_string()` - all base string construction paths
- [ ] `OAuth1Validator._compute_signature()` - all signature methods
- [ ] `OAuth2Validator._validate_introspection_endpoint()` - all validation paths
- [ ] `OAuth2Validator.validate()` - JWT validation path
- [ ] `OAuth2Validator.validate()` - introspection path
- [ ] `RecaptchaValidator._extract_token()` - token extraction from body
- [ ] `RecaptchaValidator.validate()` - v2 validation
- [ ] `RecaptchaValidator.validate()` - v3 validation with score
- [ ] `DigestAuthValidator._parse_digest_header()` - all parsing paths
- [ ] `IPWhitelistValidator._get_client_ip()` - all IP extraction paths
- [ ] `IPWhitelistValidator._normalize_ip()` - IPv6 normalization

---

### 10. `src/webhook.py` - 85% coverage (34 missing statements)

**Missing Coverage Areas:**
- [ ] `TaskManager.create_task()` - all task creation paths
- [ ] `TaskManager.get_stats()` - stats retrieval
- [ ] `WebhookHandler.__init__()` - all initialization paths
- [ ] `WebhookHandler.validate_webhook()` - all validation paths
- [ ] `WebhookHandler.process_webhook()` - all processing paths
- [ ] `WebhookHandler.process_webhook()` - chain processing
- [ ] `WebhookHandler.process_webhook()` - error handling

---

### 11. Other Files with Missing Coverage

#### `src/config_watcher.py` - 79% coverage (20 missing)
- [ ] `ConfigFileWatcher._async_reload()` - all reload paths
- [ ] `ConfigFileWatcher._watch_loop()` - file watching loop
- [ ] `ConfigFileWatcher.start()` - startup
- [ ] `ConfigFileWatcher.stop()` - shutdown

#### `src/connection_pool_registry.py` - 78% coverage (37 missing)
- [ ] `ConnectionPoolRegistry.get_pool()` - all pool retrieval paths
- [ ] `ConnectionPoolRegistry.close_pool()` - all cleanup paths
- [ ] `ConnectionPoolRegistry.close_all_pools()` - all cleanup paths
- [ ] `ConnectionPoolRegistry.get_pool_info()` - info retrieval
- [ ] Migration timeout handling
- [ ] Pool hash collision handling

#### `src/config.py` - 83% coverage (20 missing)
- [ ] `inject_connection_details()` - all injection paths
- [ ] `_validate_connection_host()` - all validation paths
- [ ] `_validate_connection_port()` - all validation paths
- [ ] Error handling in config loading

#### `src/retry_handler.py` - 81% coverage (25 missing)
- [ ] `RetryHandler.retry()` - all retry paths
- [ ] `RetryHandler.retry()` - exponential backoff
- [ ] `RetryHandler.retry()` - error classification
- [ ] `RetryHandler.retry()` - max attempts handling

#### `src/openapi_generator.py` - 91% coverage (23 missing)
- [ ] `generate_openapi_schema()` - all schema generation paths
- [ ] `_validate_webhook_id()` - all validation paths
- [ ] `_sanitize_for_description()` - all sanitization paths
- [ ] `_validate_oauth2_endpoint()` - all validation paths

#### `src/input_validator.py` - 93% coverage (9 missing)
- [ ] `InputValidator.validate()` - all validation paths
- [ ] Edge cases in validation methods

#### Module Files with Missing Coverage:
- [ ] `src/modules/mqtt.py` - 81% (34 missing)
- [ ] `src/modules/zeromq.py` - 83% (21 missing)
- [ ] `src/modules/activemq.py` - 80% (25 missing)
- [ ] `src/modules/gcp_pubsub.py` - 85% (15 missing)
- [ ] `src/modules/websocket.py` - 90% (11 missing)
- [ ] `src/modules/redis_rq.py` - 79% (17 missing)
- [ ] `src/modules/redis_publish.py` - 93% (9 missing)
- [ ] `src/modules/kafka.py` - 93% (5 missing)
- [ ] `src/modules/clickhouse.py` - 90% (10 missing)
- [ ] `src/modules/http_webhook.py` - 93% (13 missing)
- [ ] `src/modules/save_to_disk.py` - 89% (9 missing)
- [ ] `src/modules/log.py` - 93% (6 missing)
- [ ] `src/modules/base.py` - 87% (3 missing)
- [ ] `src/modules/registry.py` - 97% (2 missing)

---

## Summary by Category

### High Priority (Low Coverage, Critical Code)
1. **main.py** (57%) - Core application logic, startup/shutdown, endpoints
2. **analytics_processor.py** (58%) - Analytics processing service
3. **s3.py** (58%) - S3 storage module
4. **clickhouse_analytics.py** (62%) - Analytics database operations
5. **mysql.py** (66%) - Database module
6. **postgres.py** (69%) - Database module
7. **config_manager.py** (68%) - Configuration management

### Medium Priority (Good Coverage, Some Gaps)
8. **utils.py** (81%) - Utility functions
9. **validators.py** (91%) - Authentication validators
10. **webhook.py** (85%) - Core webhook processing
11. **config_watcher.py** (79%) - File watching
12. **connection_pool_registry.py** (78%) - Connection pooling

### Low Priority (High Coverage, Minor Gaps)
- Most module files (85-97% coverage)
- Input validator (93%)
- OpenAPI generator (91%)
- Retry handler (81%)

---

## Recommended Testing Strategy

### Phase 1: Critical Paths (Target: 95% coverage)
1. **main.py** - Startup/shutdown handlers, endpoint error paths
2. **config_manager.py** - All reload and validation paths
3. **webhook.py** - All processing paths

### Phase 2: Database Modules (Target: 90% coverage)
4. **postgres.py** - All storage modes and operations
5. **mysql.py** - All storage modes and operations
6. **clickhouse_analytics.py** - All connection and save operations

### Phase 3: Storage Modules (Target: 90% coverage)
7. **s3.py** - All upload and error paths
8. **analytics_processor.py** - All processing paths

### Phase 4: Utilities and Validators (Target: 95% coverage)
9. **utils.py** - All utility functions
10. **validators.py** - All validator edge cases

### Phase 5: Remaining Modules (Target: 95% coverage)
11. All other module files with < 95% coverage

---

## Test Types Needed

### Integration Tests
- Startup/shutdown event handlers
- Connection validation
- Database operations (PostgreSQL, MySQL, ClickHouse)
- S3 uploads
- Analytics processing

### Unit Tests
- Error handling paths
- Edge cases in validation
- Configuration parsing
- Utility functions
- Validator edge cases

### Mock-Based Tests
- External service interactions (S3, databases, message queues)
- Error scenarios
- Timeout handling
- Connection failures

---

## Notes

- **Performance test files** are excluded from coverage (by design)
- **Legacy functions** (`save_to_disk`, `print_to_stdout`) may be unused - verify before testing
- **Error paths** are often the least tested - focus on exception handling
- **Edge cases** in validation functions need more coverage
- **Integration tests** are needed for database and storage modules

---

**Total Missing Statements: ~1,200+ statements across all files**

**Estimated Test Cases Needed: ~300-400 new test cases**

