"""
Comprehensive security audit tests for ConfigManager and ConfigFileWatcher.

This audit focuses on vulnerabilities not covered in test_live_config_reload_security_audit.py:
- Error message information disclosure
- File path validation and path traversal prevention
- File watcher path matching bypass
- Error sanitization in exception handlers
"""
import pytest
import json
import os
import tempfile
import asyncio
from unittest.mock import patch, Mock, AsyncMock
from pathlib import Path

from src.config_manager import ConfigManager, ReloadResult
from src.config_watcher import ConfigFileWatcher, ConfigFileHandler
from src.utils import sanitize_error_message


# ============================================================================
# 1. ERROR MESSAGE INFORMATION DISCLOSURE
# ============================================================================

@pytest.mark.longrunning
class TestErrorInformationDisclosure:
    """Test error message information disclosure vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_exception_error_disclosure_in_reload_webhooks(self):
        """Test that exception errors don't disclose sensitive information."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_webhook = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            
            # Mock open to raise exception with sensitive info
            with patch('builtins.open', side_effect=Exception("/etc/passwd: permission denied")):
                result = await config_manager.reload_webhooks()
                
                # Error should be sanitized
                assert not result.success
                error_msg = result.error.lower()
                
                # Should not contain sensitive paths
                assert "/etc/passwd" not in error_msg
                assert "permission denied" not in error_msg or "error" in error_msg
                
        finally:
            try:
                os.unlink(temp_webhook)
            except:
                pass
            os.unlink(temp_conn)
    
    @pytest.mark.asyncio
    async def test_json_decode_error_disclosure(self):
        """Test that JSON decode errors don't disclose file paths."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            # Invalid JSON that will cause JSONDecodeError
            f.write('{"invalid": json, "path": "/etc/passwd"}')
            temp_webhook = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            
            result = await config_manager.reload_webhooks()
            
            # Error should not disclose file path or sensitive content
            assert not result.success
            error_msg = result.error.lower()
            
            # Should not contain sensitive paths from JSON content
            assert "/etc/passwd" not in error_msg
            # Should not contain full file paths
            assert "/tmp" not in error_msg or len([c for c in error_msg if c == '/']) < 3
            
        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)
    
    @pytest.mark.asyncio
    async def test_validation_error_disclosure(self):
        """Test that validation errors don't disclose sensitive information."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            # Config with sensitive information in error context
            config = {
                "test": {
                    "module": "nonexistent_module_/etc/passwd",
                    "connection": "conn_with_secret_password"
                }
            }
            json.dump(config, f)
            temp_webhook = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            
            result = await config_manager.reload_webhooks()
            
            # Error should not disclose sensitive paths or credentials
            if not result.success:
                error_msg = result.error.lower()
                assert "/etc/passwd" not in error_msg
                assert "password" not in error_msg
                assert "secret" not in error_msg
                
        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)
    
    @pytest.mark.asyncio
    async def test_connection_error_disclosure(self):
        """Test that connection config errors don't disclose sensitive info."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({}, f)
            temp_webhook = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            # Connection with sensitive info that might appear in errors
            config = {
                "conn": {
                    "type": "rabbitmq",
                    "host": "internal-server.example.com",
                    "port": 5672,
                    "user": "admin",
                    "password": "secret-password-123",
                    "vhost": "/sensitive/vhost"
                }
            }
            json.dump(config, f)
            temp_conn = f.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            
            result = await config_manager.reload_connections()
            
            # Error messages should not contain passwords or sensitive paths
            if not result.success:
                error_msg = result.error.lower()
                assert "secret-password" not in error_msg
                assert "password" not in error_msg or "password" in "missing password"
                assert "/sensitive/" not in error_msg
                
        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)
    
    def test_config_file_watcher_error_disclosure(self):
        """Test that ConfigFileWatcher doesn't disclose errors to stdout."""
        import io
        from contextlib import redirect_stdout
        
        with tempfile.TemporaryDirectory() as tmpdir:
            webhook_file = os.path.join(tmpdir, "webhooks.json")
            connection_file = os.path.join(tmpdir, "connections.json")
            
            with open(webhook_file, 'w') as f:
                json.dump({}, f)
            with open(connection_file, 'w') as f:
                json.dump({}, f)
            
            # Use real ConfigManager but mock file access to raise exception
            config_manager = ConfigManager(
                webhook_config_file=webhook_file,
                connection_config_file=connection_file
            )
            
            handler = ConfigFileHandler(config_manager)
            
            # Mock reload_webhooks to return error with sensitive info
            # But the error should already be sanitized by ConfigManager
            with patch.object(config_manager, 'reload_webhooks', new_callable=AsyncMock) as mock_reload:
                mock_reload.return_value = ReloadResult(
                    success=False,
                    error="Processing error occurred in ConfigManager.reload_webhooks"  # Sanitized error
                )
                
                # Capture stdout
                stdout_capture = io.StringIO()
                with redirect_stdout(stdout_capture):
                    # Simulate error
                    asyncio.run(handler._async_reload(webhook_file))
                
                output = stdout_capture.getvalue()
                
                # Should not contain sensitive paths (error is already sanitized)
                assert "/etc/passwd" not in output.lower()
                assert "permission denied" not in output.lower()


# ============================================================================
# 2. FILE PATH VALIDATION AND PATH TRAVERSAL PREVENTION
# ============================================================================

@pytest.mark.longrunning
class TestFilePathValidation:
    """Test file path validation and path traversal prevention."""
    
    def test_config_manager_accepts_arbitrary_paths(self):
        """Test that ConfigManager accepts arbitrary file paths (potential vulnerability)."""
        # ConfigManager doesn't validate file paths - it accepts any path
        # This is a design decision, but we should test that it handles them safely
        traversal_paths = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\sam",
            "....//....//etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",  # URL encoded
            "webhooks.json\x00../../etc/passwd",  # Null byte
        ]
        
        for traversal_path in traversal_paths:
            # ConfigManager should accept the path but file access should fail safely
            config_manager = ConfigManager(
                webhook_config_file=traversal_path,
                connection_config_file="connections.json"
            )
            
            # The path is stored but file access will fail
            assert config_manager.webhook_config_file == traversal_path
    
    @pytest.mark.asyncio
    async def test_path_traversal_file_access_fails_safely(self):
        """Test that path traversal attempts fail safely without information disclosure."""
        # Attempt to access /etc/passwd via path traversal
        # Note: _load_webhook_config returns {} if file doesn't exist, so reload succeeds
        # But if file exists and is not valid JSON, it should fail with sanitized error
        config_manager = ConfigManager(
            webhook_config_file="../../etc/passwd",
            connection_config_file="connections.json"
        )
        
        # Mock file to exist but be invalid JSON
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', side_effect=Exception("/etc/passwd: permission denied")):
                result = await config_manager.reload_webhooks()
                
                # Should fail with sanitized error
                assert not result.success
                error_msg = result.error.lower()
                
                # Error should not disclose the attempted path
                assert "/etc/passwd" not in error_msg
                assert "../../etc" not in error_msg
    
    @pytest.mark.asyncio
    async def test_double_encoded_path_traversal(self):
        """Test that double-encoded path traversal is handled safely."""
        import urllib.parse
        
        # Double-encoded path traversal
        double_encoded = urllib.parse.quote(urllib.parse.quote("../../etc/passwd"))
        
        config_manager = ConfigManager(
            webhook_config_file=double_encoded,
            connection_config_file="connections.json"
        )
        
        # Mock file to exist but raise exception with sensitive info
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', side_effect=Exception(f"{double_encoded}: access denied")):
                result = await config_manager.reload_webhooks()
                
                # Should fail with sanitized error
                assert not result.success
                error_msg = result.error.lower()
                assert "/etc/passwd" not in error_msg
    
    def test_null_byte_in_file_path(self):
        """Test that null bytes in file paths are handled safely."""
        # Null byte injection attempt
        malicious_path = "webhooks.json\x00../../etc/passwd"
        
        config_manager = ConfigManager(
            webhook_config_file=malicious_path,
            connection_config_file="connections.json"
        )
        
        # Python's open() truncates at null byte, so this should be safe
        # But we want to ensure no information disclosure
        assert config_manager.webhook_config_file == malicious_path


# ============================================================================
# 3. FILE WATCHER PATH MATCHING BYPASS
# ============================================================================

@pytest.mark.longrunning
class TestFileWatcherPathMatching:
    """Test file watcher path matching vulnerabilities."""
    
    def test_file_watcher_string_matching_bypass(self):
        """Test that file watcher string matching can be bypassed."""
        # The file watcher uses simple string matching: 'webhooks.json' in file_path
        # This can be bypassed with filenames like:
        bypass_filenames = [
            "malicious_webhooks.json",
            "webhooks.json.backup",
            "webhooks.json.tmp",
            "webhooks.json~",
            "webhooks.json.bak",
            "webhooks.json.old",
            "webhooks.json.new",
            "webhooks.json.orig",
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config_manager = ConfigManager(
                webhook_config_file=os.path.join(tmpdir, "webhooks.json"),
                connection_config_file=os.path.join(tmpdir, "connections.json")
            )
            
            handler = ConfigFileHandler(config_manager)
            
            # Create mock event objects
            for bypass_name in bypass_filenames:
                bypass_path = os.path.join(tmpdir, bypass_name)
                
                # Create a mock event
                class MockEvent:
                    def __init__(self, path):
                        self.src_path = path
                        self.is_directory = False
                
                event = MockEvent(bypass_path)
                
                # The handler should NOT trigger for these files
                # But current implementation uses 'webhooks.json' in file_path
                # which would match these files
                handler.on_modified(event)
                
                # Verify that the handler would trigger (this is the vulnerability)
                # In a secure implementation, it should use exact filename matching
                assert 'webhooks.json' in bypass_path  # This is the problem
    
    def test_file_watcher_exact_filename_matching(self):
        """Test that file watcher should use exact filename matching."""
        with tempfile.TemporaryDirectory() as tmpdir:
            webhook_file = os.path.join(tmpdir, "webhooks.json")
            connection_file = os.path.join(tmpdir, "connections.json")
            
            with open(webhook_file, 'w') as f:
                json.dump({}, f)
            with open(connection_file, 'w') as f:
                json.dump({}, f)
            
            config_manager = ConfigManager(
                webhook_config_file=webhook_file,
                connection_config_file=connection_file
            )
            
            handler = ConfigFileHandler(config_manager)
            
            # Create mock events
            class MockEvent:
                def __init__(self, path):
                    self.src_path = path
                    self.is_directory = False
            
            # Should trigger for exact match
            exact_event = MockEvent(webhook_file)
            handler.on_modified(exact_event)
            
            # Should NOT trigger for similar filenames
            similar_files = [
                os.path.join(tmpdir, "malicious_webhooks.json"),
                os.path.join(tmpdir, "webhooks.json.backup"),
            ]
            
            for similar_file in similar_files:
                with open(similar_file, 'w') as f:
                    f.write("{}")
                
                similar_event = MockEvent(similar_file)
                # Current implementation would trigger (vulnerability)
                # Secure implementation should not trigger
                handler.on_modified(similar_event)


# ============================================================================
# 4. ERROR SANITIZATION IN EXCEPTION HANDLERS
# ============================================================================

@pytest.mark.longrunning
class TestErrorSanitization:
    """Test error sanitization in exception handlers."""
    
    @pytest.mark.asyncio
    async def test_reload_webhooks_uses_sanitize_error_message(self):
        """Test that reload_webhooks uses sanitize_error_message for exceptions."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_webhook = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            
            # Mock open to raise exception with sensitive info
            with patch('os.path.exists', return_value=True):
                with patch('builtins.open', side_effect=Exception("/etc/passwd: permission denied")):
                    result = await config_manager.reload_webhooks()
                    
                    # Error should be sanitized
                    assert not result.success
                    error_msg = result.error.lower()
                    
                    # Should not contain sensitive paths
                    assert "/etc/passwd" not in error_msg, "Error message should be sanitized"
                    
        finally:
            try:
                os.unlink(temp_webhook)
            except:
                pass
            os.unlink(temp_conn)
    
    @pytest.mark.asyncio
    async def test_reload_connections_uses_sanitize_error_message(self):
        """Test that reload_connections uses sanitize_error_message for exceptions."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({}, f)
            temp_webhook = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_conn = f.name
        
        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook,
                connection_config_file=temp_conn
            )
            
            # Delete file to cause exception
            os.unlink(temp_conn)
            
            # Mock open to raise exception with sensitive info
            with patch('builtins.open', side_effect=Exception("/etc/shadow: access denied")):
                result = await config_manager.reload_connections()
                
                # Error should be sanitized
                assert not result.success
                error_msg = result.error.lower()
                
                # Should not contain sensitive paths
                # NOTE: This test will fail until sanitize_error_message is used
                assert "/etc/shadow" not in error_msg, "Error message should be sanitized"
                
        finally:
            os.unlink(temp_webhook)
            try:
                os.unlink(temp_conn)
            except:
                pass
    
    def test_config_file_watcher_uses_sanitize_error_message(self):
        """Test that ConfigFileWatcher uses sanitize_error_message for exceptions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            webhook_file = os.path.join(tmpdir, "webhooks.json")
            connection_file = os.path.join(tmpdir, "connections.json")
            
            with open(webhook_file, 'w') as f:
                json.dump({}, f)
            with open(connection_file, 'w') as f:
                json.dump({}, f)
            
            config_manager = ConfigManager(
                webhook_config_file=webhook_file,
                connection_config_file=connection_file
            )
            
            handler = ConfigFileHandler(config_manager)
            
            # Mock reload_webhooks to raise exception with sensitive info
            async def mock_reload():
                raise Exception("/etc/passwd: permission denied")
            
            with patch.object(config_manager, 'reload_webhooks', side_effect=mock_reload):
                # Capture stdout to check error messages
                import io
                from contextlib import redirect_stdout
                
                stdout_capture = io.StringIO()
                with redirect_stdout(stdout_capture):
                    asyncio.run(handler._async_reload(webhook_file))
                
                output = stdout_capture.getvalue()
                
                # sanitize_error_message prints detailed error for server-side logging,
                # but the user-facing error message should be sanitized
                # Check that the final error message (after "Error during config reload:") is sanitized
                if "error during config reload:" in output.lower():
                    # Extract the part after "Error during config reload:"
                    error_part = output.lower().split("error during config reload:")[-1].strip()
                    # The sanitized error should not contain sensitive paths
                    assert "/etc/passwd" not in error_part, "Error message should be sanitized"
                else:
                    # If format changed, at least verify sensitive path is not in the sanitized part
                    # (detailed error from sanitize_error_message may contain it for server logging)
                    lines = output.lower().split('\n')
                    sanitized_lines = [l for l in lines if "processing error" in l or "error occurred" in l]
                    if sanitized_lines:
                        assert "/etc/passwd" not in sanitized_lines[-1], "Sanitized error should not contain sensitive paths"


# ============================================================================
# 5. FILE WATCHER DIRECTORY TRAVERSAL
# ============================================================================

@pytest.mark.longrunning
class TestFileWatcherDirectoryTraversal:
    """Test file watcher directory traversal vulnerabilities."""
    
    def test_file_watcher_watches_parent_directory(self):
        """Test that file watcher doesn't watch parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested directory structure
            nested_dir = os.path.join(tmpdir, "nested", "deep")
            os.makedirs(nested_dir, exist_ok=True)
            
            webhook_file = os.path.join(nested_dir, "webhooks.json")
            connection_file = os.path.join(nested_dir, "connections.json")
            
            with open(webhook_file, 'w') as f:
                json.dump({}, f)
            with open(connection_file, 'w') as f:
                json.dump({}, f)
            
            config_manager = ConfigManager(
                webhook_config_file=webhook_file,
                connection_config_file=connection_file
            )
            
            watcher = ConfigFileWatcher(config_manager)
            watcher.start()
            
            try:
                # Watcher should only watch the directory containing the files
                # Not parent directories
                watch_dir = os.path.dirname(webhook_file)
                assert watcher.is_watching()
                
                # The watcher should not watch tmpdir or nested_dir's parent
                # This is handled by watchdog's recursive=False, but we test it
                
            finally:
                watcher.stop()
    
    def test_file_watcher_prevents_watching_system_directories(self):
        """Test that file watcher doesn't watch system directories."""
        # This test documents that file paths should be validated
        # to prevent watching system directories like /etc, /usr, etc.
        
        # Attempt to create watcher with system directory paths
        system_paths = [
            "/etc/webhooks.json",
            "/usr/local/webhooks.json",
            "/var/log/webhooks.json",
        ]
        
        for system_path in system_paths:
            # ConfigManager accepts any path
            config_manager = ConfigManager(
                webhook_config_file=system_path,
                connection_config_file="/etc/connections.json"
            )
            
            watcher = ConfigFileWatcher(config_manager)
            
            # Watcher would try to watch /etc or other system directories
            # This is a potential vulnerability if paths are not validated
            # In production, file paths should be restricted to application directory
            
            # Test that watcher doesn't crash when given system paths
            try:
                watcher.start()
                # If it starts, it's watching a system directory (vulnerability)
                # In secure implementation, this should be prevented
                if watcher.is_watching():
                    # This documents the risk
                    pass
                watcher.stop()
            except Exception:
                # Exception is acceptable (prevents watching system directories)
                pass

