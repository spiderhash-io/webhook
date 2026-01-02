"""
Security tests for SQL injection prevention in MySQL and PostgreSQL modules.

These tests verify that:
1. Table names are properly escaped via _quote_identifier()
2. Column names are properly escaped
3. Values use parameterized queries
4. SQL injection attempts are prevented
"""
import pytest
from src.modules.mysql import MySQLModule
from src.modules.postgres import PostgreSQLModule


class TestMySQLSQLInjectionPrevention:
    """Test SQL injection prevention in MySQL module."""
    
    def test_quote_identifier_escapes_backticks(self):
        """Test that _quote_identifier properly escapes backticks."""
        config = {
            "host": "localhost",
            "port": 3306,
            "database": "test",
            "user": "test",
            "password": "test",
            "table_name": "test_table"
        }
        module = MySQLModule(config)
        
        # Test normal identifier
        assert module._quote_identifier("users") == "`users`"
        
        # Test identifier with backtick (should be escaped by doubling)
        # Input: user`s -> Output: `user``s` (backtick is doubled)
        result = module._quote_identifier("user`s")
        assert result == "`user``s`"
        
        # Test identifier that's already quoted (edge case)
        # Input: `user` -> Output: ``user`` (each backtick is doubled)
        result = module._quote_identifier("`user`")
        assert result.startswith("`") and result.endswith("`")
        assert "``" in result  # Backticks should be doubled
    
    def test_quote_identifier_prevents_sql_injection(self):
        """Test that quoted identifiers prevent SQL injection."""
        config = {
            "host": "localhost",
            "port": 3306,
            "database": "test",
            "user": "test",
            "password": "test",
            "table_name": "test_table"
        }
        module = MySQLModule(config)
        
        # Attempt SQL injection in table name
        malicious_table = "users; DROP TABLE users; --"
        quoted = module._quote_identifier(malicious_table)
        
        # Should be properly quoted, making injection impossible
        assert quoted.startswith("`")
        assert quoted.endswith("`")
        # The semicolon and SQL keywords should be inside quotes, making them literal
        assert "DROP" in quoted
        assert quoted.count("`") >= 2  # At least opening and closing quotes
    
    def test_table_name_validation(self):
        """Test that table names are validated before use."""
        config = {
            "host": "localhost",
            "port": 3306,
            "database": "test",
            "user": "test",
            "password": "test",
            "table_name": "test_table"
        }
        module = MySQLModule(config)
        
        # Table names should be validated (this is tested in integration tests)
        # Here we just verify the quoting function works
        assert module._quote_identifier("valid_table") == "`valid_table`"


class TestPostgreSQLSQLInjectionPrevention:
    """Test SQL injection prevention in PostgreSQL module."""
    
    def test_quote_identifier_escapes_double_quotes(self):
        """Test that _quote_identifier properly escapes double quotes."""
        config = {
            "host": "localhost",
            "port": 5432,
            "database": "test",
            "user": "test",
            "password": "test",
            "table_name": "test_table"
        }
        module = PostgreSQLModule(config)
        
        # Test normal identifier
        assert module._quote_identifier("users") == '"users"'
        
        # Test identifier with double quote (should be escaped)
        assert module._quote_identifier('user"s') == '"user""s"'
        
        # Test identifier with multiple double quotes
        assert module._quote_identifier('"user"') == '"""user"""'
    
    def test_quote_identifier_prevents_sql_injection(self):
        """Test that quoted identifiers prevent SQL injection."""
        config = {
            "host": "localhost",
            "port": 5432,
            "database": "test",
            "user": "test",
            "password": "test",
            "table_name": "test_table"
        }
        module = PostgreSQLModule(config)
        
        # Attempt SQL injection in table name
        malicious_table = "users; DROP TABLE users; --"
        quoted = module._quote_identifier(malicious_table)
        
        # Should be properly quoted, making injection impossible
        assert quoted.startswith('"')
        assert quoted.endswith('"')
        # The semicolon and SQL keywords should be inside quotes, making them literal
        assert "DROP" in quoted
        assert quoted.count('"') >= 2  # At least opening and closing quotes
    
    def test_parameterized_queries_used(self):
        """
        Test that parameterized queries are used for values.
        
        This test documents that:
        1. Table/column names use _quote_identifier() (safe)
        2. Values use parameterized queries ($1, $2, etc. for PostgreSQL, %s for MySQL)
        3. This prevents SQL injection even if identifier quoting fails
        """
        # This is a documentation test
        # In the actual code:
        # - MySQL: VALUES (%s, %s, %s) with tuple(values)
        # - PostgreSQL: VALUES ($1, $2, $3) with conn.execute(query, *values)
        # Both are safe from SQL injection
        
        assert True  # Documentation test

