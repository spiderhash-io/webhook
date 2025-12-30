"""
Security tests for ClickHouse module.
Tests table name validation to prevent SQL injection.
"""
import pytest
from src.modules.clickhouse import ClickHouseModule


class TestClickHouseSecurity:
    """Test suite for ClickHouse module security."""
    
    def test_valid_table_names(self):
        """Test that valid table names are accepted."""
        valid_names = [
            "webhook_logs",
            "webhook_logs_2024",
            "webhook_logs_test",
            "WebhookLogs",
            "webhook123",
            "a",
            "A" * 100,  # Long but valid
        ]
        
        for table_name in valid_names:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": table_name
                }
            }
            module = ClickHouseModule(config)
            assert module.table_name == table_name
    
    def test_sql_injection_attempts(self):
        """Test that SQL injection attempts in table names are rejected."""
        injection_attempts = [
            "webhook_logs; DROP TABLE webhook_logs; --",
            "webhook_logs'; DROP TABLE webhook_logs; --",
            "webhook_logs\"; DROP TABLE webhook_logs; --",
            "webhook_logs; DELETE FROM webhook_logs; --",
            "webhook_logs UNION SELECT * FROM users",
            "webhook_logs' OR '1'='1",
            "webhook_logs; EXEC xp_cmdshell('dir'); --",
            "webhook_logs; SELECT * FROM users; --",
        ]
        
        for malicious_name in injection_attempts:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": malicious_name
                }
            }
            with pytest.raises(ValueError) as exc_info:
                ClickHouseModule(config)
            assert "Invalid table name" in str(exc_info.value) or "forbidden keyword" in str(exc_info.value) or "dangerous pattern" in str(exc_info.value)
    
    def test_sql_keywords_rejected(self):
        """Test that SQL keywords in table names are rejected."""
        sql_keywords = [
            "SELECT",
            "INSERT",
            "DROP",
            "DELETE",
            "CREATE",
            "ALTER",
            "TRUNCATE",
            "EXEC",
            "UNION",
        ]
        
        for keyword in sql_keywords:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": f"webhook_{keyword}_logs"
                }
            }
            with pytest.raises(ValueError) as exc_info:
                ClickHouseModule(config)
            assert "forbidden keyword" in str(exc_info.value).lower()
    
    def test_dangerous_patterns_rejected(self):
        """Test that dangerous patterns are rejected."""
        dangerous_patterns = [
            "webhook..logs",  # Path traversal
            "webhook--logs",  # SQL comment
            "webhook;logs",   # Statement separator
            "webhook/*logs*/",  # SQL comment block
            "webhook_xp_logs",  # Extended procedure prefix
            "webhook_sp_logs",  # Stored procedure prefix
        ]
        
        for pattern in dangerous_patterns:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": pattern
                }
            }
            with pytest.raises(ValueError) as exc_info:
                ClickHouseModule(config)
            assert "dangerous pattern" in str(exc_info.value).lower() or "Invalid table name" in str(exc_info.value)
    
    def test_special_characters_rejected(self):
        """Test that special characters are rejected."""
        special_chars = [
            "webhook-logs",  # Hyphen
            "webhook.logs",  # Dot
            "webhook/logs",  # Slash
            "webhook\\logs",  # Backslash
            "webhook logs",  # Space
            "webhook'logs",  # Single quote
            'webhook"logs',  # Double quote
            "webhook`logs",  # Backtick
            "webhook[logs]",  # Brackets
            "webhook{logs}",  # Braces
            "webhook(logs)",  # Parentheses
        ]
        
        for name in special_chars:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": name
                }
            }
            with pytest.raises(ValueError) as exc_info:
                ClickHouseModule(config)
            assert "Invalid table name" in str(exc_info.value)
    
    def test_unicode_characters_rejected(self):
        """Test that Unicode characters are rejected."""
        unicode_names = [
            "webhook_测试_logs",
            "webhook_ログ",
            "webhook_логи",
            "webhook_📊_logs",
        ]
        
        for name in unicode_names:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": name
                }
            }
            with pytest.raises(ValueError) as exc_info:
                ClickHouseModule(config)
            assert "Invalid table name" in str(exc_info.value)
    
    def test_empty_table_name_rejected(self):
        """Test that empty table names are rejected."""
        empty_names = ["", "   ", None]
        
        for name in empty_names:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": name
                }
            }
            with pytest.raises(ValueError) as exc_info:
                ClickHouseModule(config)
            assert "empty" in str(exc_info.value).lower() or "non-empty string" in str(exc_info.value).lower()
    
    def test_table_name_length_limit(self):
        """Test that very long table names are rejected."""
        # Create a very long but valid table name
        long_name = "a" * 300  # Exceeds 255 character limit
        
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": long_name
            }
        }
        with pytest.raises(ValueError) as exc_info:
            ClickHouseModule(config)
        assert "too long" in str(exc_info.value).lower()
    
    def test_table_name_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        # Whitespace should be stripped
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "  webhook_logs  "
            }
        }
        module = ClickHouseModule(config)
        assert module.table_name == "webhook_logs"
        
        # But whitespace-only should be rejected
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "   "
            }
        }
        with pytest.raises(ValueError):
            ClickHouseModule(config)
    
    def test_table_name_case_sensitivity(self):
        """Test that table names are case-sensitive (preserved)."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "WebhookLogs"
            }
        }
        module = ClickHouseModule(config)
        assert module.table_name == "WebhookLogs"
    
    def test_default_table_name(self):
        """Test that default table name is used when not specified."""
        config = {
            "module": "clickhouse",
            "module-config": {}
        }
        module = ClickHouseModule(config)
        assert module.table_name == "webhook_logs"
    
    def test_table_name_with_numbers(self):
        """Test that table names with numbers are accepted."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs_2024_01"
            }
        }
        module = ClickHouseModule(config)
        assert module.table_name == "webhook_logs_2024_01"
    
    def test_table_name_underscore_only(self):
        """Test edge cases with underscores."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook__logs"  # Double underscore
            }
        }
        module = ClickHouseModule(config)
        assert module.table_name == "webhook__logs"
    
    def test_table_name_starts_with_number(self):
        """Test that table names starting with numbers are accepted."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "2024_webhook_logs"
            }
        }
        module = ClickHouseModule(config)
        assert module.table_name == "2024_webhook_logs"
    
    def test_identifier_quoting(self):
        """Test that table names are properly quoted."""
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": "webhook_logs"
            }
        }
        module = ClickHouseModule(config)
        
        # Test that _quote_identifier works correctly
        quoted = module._quote_identifier("webhook_logs")
        assert quoted == "`webhook_logs`"
        
        # Test that backticks in identifier are escaped (though they shouldn't pass validation)
        # This tests the quoting function itself
        quoted_with_backtick = module._quote_identifier("test`name")
        assert quoted_with_backtick == "`test``name`"
    
    def test_multiple_injection_attempts(self):
        """Test various SQL injection patterns."""
        injection_patterns = [
            ("'; DROP TABLE users; --", "semicolon and comment"),
            ("' OR '1'='1", "SQL OR condition"),
            ("'; EXEC xp_cmdshell('dir'); --", "command execution"),
            ("'; SELECT * FROM users; --", "data exfiltration"),
            ("'; UPDATE users SET password='hacked'; --", "data modification"),
            ("'; TRUNCATE TABLE logs; --", "data deletion"),
            ("'; CREATE TABLE evil (data String); --", "table creation"),
            ("'; ALTER TABLE logs ADD COLUMN hacked String; --", "schema modification"),
        ]
        
        for pattern, description in injection_patterns:
            config = {
                "module": "clickhouse",
                "module-config": {
                    "table": f"webhook_logs{pattern}"
                }
            }
            with pytest.raises(ValueError) as exc_info:
                ClickHouseModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "dangerous", "not allowed"
            ]), f"Failed to reject injection pattern: {description}"

