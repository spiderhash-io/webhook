"""
Config File Watcher for monitoring configuration file changes.

This module provides file system monitoring using the watchdog library
to automatically trigger config reloads when files change.
"""
import os
import asyncio
import threading
from typing import Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent


class ConfigFileHandler(FileSystemEventHandler):
    """
    Event handler for config file changes.
    
    Features:
    - Debounces rapid file changes
    - Triggers async reload operations
    - Thread-safe async task scheduling
    """
    
    def __init__(self, config_manager, debounce_seconds: float = 3.0, event_loop=None):
        """
        Initialize config file handler.
        
        Args:
            config_manager: ConfigManager instance
            debounce_seconds: Seconds to wait after last change before reloading
            event_loop: Optional asyncio event loop for scheduling tasks
        """
        self.config_manager = config_manager
        self.debounce_seconds = debounce_seconds
        self.event_loop = event_loop
        self._debounce_timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()
    
    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
        
        # Only handle webhooks.json and connections.json
        file_path = event.src_path
        if 'webhooks.json' in file_path or 'connections.json' in file_path:
            self._debounce_reload(file_path)
    
    def _debounce_reload(self, file_path: str):
        """
        Debounce reload operation to prevent excessive reloads.
        
        Args:
            file_path: Path to the modified file
        """
        with self._lock:
            # Cancel existing timer if any
            if self._debounce_timer:
                self._debounce_timer.cancel()
            
            # Create new timer
            self._debounce_timer = threading.Timer(
                self.debounce_seconds,
                self._trigger_reload,
                args=(file_path,)
            )
            self._debounce_timer.start()
    
    def _trigger_reload(self, file_path: str):
        """
        Trigger reload operation (called after debounce delay).
        
        Args:
            file_path: Path to the modified file
        """
        # Get or create event loop
        loop = self.event_loop
        if not loop:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    # No event loop available, create task in new thread
                    threading.Thread(
                        target=self._run_reload_in_thread,
                        args=(file_path,),
                        daemon=True
                    ).start()
                    return
        
        # Schedule reload task in event loop
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._async_reload(file_path),
                loop
            )
        else:
            # Fallback: run in new thread
            threading.Thread(
                target=self._run_reload_in_thread,
                args=(file_path,),
                daemon=True
            ).start()
    
    def _run_reload_in_thread(self, file_path: str):
        """Run reload in a new thread with new event loop."""
        asyncio.run(self._async_reload(file_path))
    
    async def _async_reload(self, file_path: str):
        """
        Perform async reload operation.
        
        Args:
            file_path: Path to the modified file
        """
        try:
            if 'webhooks.json' in file_path:
                result = await self.config_manager.reload_webhooks()
                if result.success:
                    print(f"Webhook config reloaded successfully: {result.details}")
                else:
                    print(f"Webhook config reload failed: {result.error}")
            elif 'connections.json' in file_path:
                result = await self.config_manager.reload_connections()
                if result.success:
                    print(f"Connection config reloaded successfully: {result.details}")
                else:
                    print(f"Connection config reload failed: {result.error}")
        except Exception as e:
            print(f"Error during config reload: {e}")


class ConfigFileWatcher:
    """
    File system watcher for configuration files.
    
    Monitors webhooks.json and connections.json for changes
    and triggers automatic reloads.
    """
    
    def __init__(self, config_manager, debounce_seconds: float = 3.0, event_loop=None):
        """
        Initialize config file watcher.
        
        Args:
            config_manager: ConfigManager instance
            debounce_seconds: Seconds to wait after last change before reloading
            event_loop: Optional asyncio event loop to use for scheduling tasks
        """
        self.config_manager = config_manager
        self.debounce_seconds = debounce_seconds
        self.observer: Optional[Observer] = None
        self.handler: Optional[ConfigFileHandler] = None
        self._watching = False
        self.event_loop = event_loop  # Initialize event_loop attribute
    
    def start(self):
        """Start watching config files."""
        if self._watching:
            return
        
        # Get directory to watch (where config files are located)
        webhook_file = self.config_manager.webhook_config_file
        connection_file = self.config_manager.connection_config_file
        
        # Use absolute paths
        webhook_path = os.path.abspath(webhook_file)
        connection_path = os.path.abspath(connection_file)
        
        # Watch the directory containing the config files
        watch_dir = os.path.dirname(webhook_path) or os.path.dirname(connection_path) or "."
        watch_dir = os.path.abspath(watch_dir)
        
        # Get or store the event loop for thread-safe scheduling
        if not self.event_loop:
            try:
                self.event_loop = asyncio.get_running_loop()
            except RuntimeError:
                try:
                    self.event_loop = asyncio.get_event_loop()
                except RuntimeError:
                    # No event loop available, will create tasks in threads
                    self.event_loop = None
        
        # Create event handler
        self.handler = ConfigFileHandler(
            self.config_manager,
            self.debounce_seconds,
            self.event_loop
        )
        
        # Create observer
        self.observer = Observer()
        self.observer.schedule(self.handler, watch_dir, recursive=False)
        self.observer.start()
        
        self._watching = True
        print(f"Config file watcher started (watching {watch_dir})")
    
    def stop(self):
        """Stop watching config files."""
        if not self._watching:
            return
        
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5.0)
            self.observer = None
        
        if self.handler and self.handler._debounce_timer:
            self.handler._debounce_timer.cancel()
        
        self._watching = False
        print("Config file watcher stopped")
    
    def is_watching(self) -> bool:
        """Check if watcher is currently active."""
        return self._watching

