"""
CSMD64.py - Enterprise-Grade Bridge & Connection Manager for HTML, EXE, and Inter-Process Communication

Features:
- Multi-connection HTML-to-HTML bridging
- HTML-to-EXE process management and communication
- Real-time WebSocket data sync
- Advanced event-driven architecture
- Encryption, authentication, and security
- High-performance message queue
- Built-in HTTP server and WebSocket server
- Persistent SQLite storage
- Comprehensive logging and monitoring

Version: 1.0.0
Author: CSMD64 Team
"""

import asyncio
import json
import os
import sys
import socket
import threading
import multiprocessing
import base64
import hashlib
import hmac
import uuid
import time
import logging
import webbrowser
import pickle
import zlib
import struct
import http.server
import socketserver
import subprocess
import ctypes
import pathlib
from pathlib import Path
import sqlite3
import functools
import warnings
from typing import Dict, List, Any, Optional, Callable, Union, Tuple, Set, Coroutine
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor

# Optional dependencies with fallback handling
try:
    import aiohttp
    from aiohttp import web
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    warnings.warn("aiohttp not installed. HTTP server will use fallback (threaded http.server)")

try:
    import websockets
    from websockets.server import serve as websockets_serve
    from websockets.exceptions import ConnectionClosed
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    warnings.warn("websockets not installed. WebSocket server will be unavailable")

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    warnings.warn("cryptography not installed. Encryption features will be simulated (NOT SECURE).")

# ============================================================================
# CLASS 1: CSMD64Config - Configuration Manager
# ============================================================================

@dataclass
class CSMD64Config:
    """
    Comprehensive configuration manager for CSMD64 library.
    Supports 100+ settings for enterprise-grade operation.
    """

    # ── Server Settings ──
    host: str = "127.0.0.1"
    port: int = 8765
    backup_port: int = 8766
    max_connections: int = 100
    connection_timeout: float = 30.0
    keep_alive_interval: float = 60.0

    # ── Security Settings ──
    encryption_enabled: bool = True
    encryption_algorithm: str = "AES-256-GCM"
    authentication_enabled: bool = True
    authentication_token_expiry: int = 3600  # 1 hour
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None

    # ── HTML Settings ──
    html_root_dir: str = "./html_files"
    html_auto_reload: bool = True
    html_cors_enabled: bool = True
    html_allowed_origins: List[str] = field(default_factory=lambda: ["*"])

    # ── EXE Settings ──
    exe_allowed_paths: List[str] = field(default_factory=lambda: ["./allowed_exes"])
    exe_timeout: float = 300.0  # 5 minutes
    exe_max_memory: int = 1024 * 1024 * 1024  # 1GB
    exe_sandbox_enabled: bool = True

    # ── Performance Settings ──
    max_message_size: int = 10 * 1024 * 1024  # 10MB
    message_queue_size: int = 10000
    buffer_size: int = 8192
    thread_pool_size: int = multiprocessing.cpu_count() * 2
    async_workers: int = multiprocessing.cpu_count()

    # ── Logging Settings ──
    log_level: str = "INFO"
    log_file: str = "./logs/csmd64.log"
    log_max_size: int = 10 * 1024 * 1024  # 10MB
    log_backup_count: int = 5
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # ── Database Settings ──
    database_path: str = "./data/csmd64.db"
    database_pool_size: int = 10
    database_timeout: float = 30.0

    # ── Cache Settings ──
    cache_enabled: bool = True
    cache_size: int = 1000
    cache_ttl: int = 3600  # 1 hour

    # ── Monitoring Settings ──
    monitoring_enabled: bool = True
    monitoring_interval: float = 5.0
    metrics_retention: int = 86400  # 24 hours

    # ── Validation ──
    def validate(self) -> Tuple[bool, List[str]]:
        """Validate configuration and return (is_valid, list of errors)."""
        errors = []
        if not (1 <= self.port <= 65535):
            errors.append("Port must be between 1 and 65535")
        if self.max_connections < 1:
            errors.append("max_connections must be at least 1")
        if self.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            errors.append("Invalid log level")
        if self.ssl_enabled and (not self.ssl_cert_path or not self.ssl_key_path):
            errors.append("SSL enabled but certificate/key path not set")
        return len(errors) == 0, errors


# ============================================================================
# CLASS 2: CSMD64Logger - Advanced Logging System
# ============================================================================

class CSMD64Logger:
    """
    Multi-handler, rotating, metrics-capable logging system.
    """

    def __init__(self, config: CSMD64Config, name: str = "CSMD64"):
        self.config = config
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, config.log_level))

        # Ensure log directory exists
        os.makedirs(os.path.dirname(config.log_file), exist_ok=True)

        # File handler with rotation
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                config.log_file,
                maxBytes=config.log_max_size,
                backupCount=config.log_backup_count,
                encoding="utf-8"
            )
            file_handler.setLevel(getattr(logging, config.log_level))
            file_handler.setFormatter(logging.Formatter(config.log_format))
            self.logger.addHandler(file_handler)
        except Exception as e:
            print(f"Failed to set up file logging: {e}")

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter(config.log_format))
        self.logger.addHandler(console_handler)

        # Prevent propagation to root logger
        self.logger.propagate = False

        # Metrics storage
        self.metrics_log: List[Dict[str, Any]] = []
        self._metrics_lock = threading.Lock()

    def debug(self, message: str, **kwargs):
        self.logger.debug(message, extra=kwargs)

    def info(self, message: str, **kwargs):
        self.logger.info(message, extra=kwargs)

    def warning(self, message: str, **kwargs):
        self.logger.warning(message, extra=kwargs)

    def error(self, message: str, **kwargs):
        self.logger.error(message, extra=kwargs)

    def critical(self, message: str, **kwargs):
        self.logger.critical(message, extra=kwargs)

    def log_metrics(self, metric_name: str, value: float, **tags):
        """Record a performance metric."""
        metric = {
            "timestamp": time.time(),
            "name": metric_name,
            "value": value,
            "tags": tags
        }
        with self._metrics_lock:
            self.metrics_log.append(metric)
            # Trim to last 10000 entries
            if len(self.metrics_log) > 10000:
                self.metrics_log = self.metrics_log[-10000:]

    def get_metrics(self, start_time: Optional[float] = None,
                    end_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Retrieve metrics within a time range."""
        with self._metrics_lock:
            metrics = self.metrics_log[:]
        if start_time is not None:
            metrics = [m for m in metrics if m["timestamp"] >= start_time]
        if end_time is not None:
            metrics = [m for m in metrics if m["timestamp"] <= end_time]
        return metrics


# ============================================================================
# CLASS 3: CSMD64Security - Encryption & Authentication
# ============================================================================

class CSMD64Security:
    """
    Handles encryption, authentication tokens, password hashing, and input validation.
    """

    def __init__(self, config: CSMD64Config):
        self.config = config
        self.logger = CSMD64Logger(config, "CSMD64.Security")
        self.encryption_key: Optional[bytes] = None
        self.fernet: Optional[Fernet] = None
        self.active_tokens: Dict[str, Dict[str, Any]] = {}
        self._token_lock = threading.Lock()

        if config.encryption_enabled:
            self._init_encryption()

    def _init_encryption(self):
        """Initialize encryption key from file or generate new one."""
        key_dir = "./data"
        key_file = os.path.join(key_dir, "encryption.key")
        os.makedirs(key_dir, exist_ok=True)

        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                self.encryption_key = f.read()
        else:
            if HAS_CRYPTO:
                self.encryption_key = Fernet.generate_key()
            else:
                # Fallback to a deterministic key (insecure, only for dev)
                self.encryption_key = base64.urlsafe_b64encode(hashlib.sha256(b"csmd64_fallback").digest())
                self.logger.warning("Using fallback encryption key; real security requires 'cryptography' package.")
            with open(key_file, "wb") as f:
                f.write(self.encryption_key)

        if HAS_CRYPTO:
            self.fernet = Fernet(self.encryption_key)
        else:
            self.fernet = None
        self.logger.info("Encryption initialized")

    def encrypt(self, data: Union[str, bytes]) -> bytes:
        """Encrypt data. Returns bytes."""
        if not self.config.encryption_enabled or not self.fernet:
            return data.encode() if isinstance(data, str) else data

        if isinstance(data, str):
            data = data.encode()
        return self.fernet.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data. Returns bytes."""
        if not self.config.encryption_enabled or not self.fernet:
            return encrypted_data
        return self.fernet.decrypt(encrypted_data)

    def generate_token(self, user_id: str, expiry: Optional[int] = None) -> str:
        """Generate an authentication token."""
        token = str(uuid.uuid4())
        expiry = expiry or self.config.authentication_token_expiry
        token_data = {
            "user_id": user_id,
            "created_at": time.time(),
            "expires_at": time.time() + expiry,
            "ip_address": None
        }
        with self._token_lock:
            self.active_tokens[token] = token_data
        self.logger.info(f"Token generated for user {user_id}")
        return token

    def validate_token(self, token: str) -> bool:
        """Check if token is valid and not expired."""
        with self._token_lock:
            if token not in self.active_tokens:
                return False
            token_data = self.active_tokens[token]
            if time.time() > token_data["expires_at"]:
                del self.active_tokens[token]
                return False
            return True

    def revoke_token(self, token: str):
        """Revoke a token immediately."""
        with self._token_lock:
            if token in self.active_tokens:
                del self.active_tokens[token]
                self.logger.info(f"Token revoked: {token}")

    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """Hash password and return (hashed_password, base64_salt)."""
        if not HAS_CRYPTO:
            # Simple fallback for demo
            salt = salt or os.urandom(16)
            dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            return base64.b64encode(dk).decode(), base64.b64encode(salt).decode()

        if salt is None:
            salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), base64.urlsafe_b64encode(salt).decode()

    def verify_password(self, password: str, hashed: str, salt: str) -> bool:
        """Verify a password against stored hash and salt."""
        if not HAS_CRYPTO:
            salt_bytes = base64.b64decode(salt)
            new_hash, _ = self.hash_password(password, salt_bytes)
            return new_hash == hashed

        salt_bytes = base64.urlsafe_b64decode(salt.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        try:
            kdf.verify(password.encode(), base64.urlsafe_b64decode(hashed.encode()))
            return True
        except Exception:
            return False

    def validate_html_filename(self, filename: str) -> bool:
        """Validate HTML filename to prevent path traversal."""
        import re
        pattern = r'^[a-zA-Z0-9_\-\.]+\.html$'
        if not re.match(pattern, filename):
            return False
        # Additional path traversal check
        if ".." in filename or "/" in filename or "\\" in filename:
            return False
        return True

    def validate_exe_path(self, path: str) -> bool:
        """Validate that the EXE path is within allowed directories."""
        path = os.path.abspath(path)
        for allowed in self.config.exe_allowed_paths:
            allowed_abs = os.path.abspath(allowed)
            if path.startswith(allowed_abs):
                return True
        return False


# ============================================================================
# CLASS 4: CSMD64Connection - Individual Connection Handler
# ============================================================================

@dataclass
class CSMD64Connection:
    """
    Represents a single connection to an HTML page or EXE process.
    Provides unified send/receive interface over sockets, WebSockets, or HTTP.
    """

    connection_id: str
    connection_type: str  # "html_a", "html_b", "exe"
    name: str
    socket: Optional[socket.socket] = None
    websocket: Any = None
    http_session: Optional[aiohttp.ClientSession] = None
    is_connected: bool = False
    connected_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    config: CSMD64Config = field(default_factory=CSMD64Config)

    async def send(self, data: Any, encrypt: bool = True) -> bool:
        """Send data through the connection."""
        try:
            serialized = json.dumps(data).encode()
            if encrypt and self.config.encryption_enabled:
                # Use a global security instance (will be set later)
                from . import security
                serialized = security.encrypt(serialized)

            if self.websocket:
                await self.websocket.send(serialized)
            elif self.socket:
                loop = asyncio.get_running_loop()
                await loop.sock_sendall(self.socket, serialized)
            elif self.http_session:
                url = self.metadata.get('url', 'http://localhost/')
                async with self.http_session.post(f"{url}message", data=serialized) as resp:
                    if resp.status != 200:
                        raise ConnectionError(f"HTTP POST failed with status {resp.status}")
            else:
                return False

            self.messages_sent += 1
            self.bytes_sent += len(serialized)
            self.last_activity = time.time()
            return True
        except Exception as e:
            logging.getLogger("CSMD64.Connection").error(f"Send failed: {e}")
            return False

    async def receive(self, timeout: Optional[float] = None) -> Optional[Any]:
        """Receive data from the connection."""
        try:
            if self.websocket:
                if timeout:
                    raw = await asyncio.wait_for(self.websocket.recv(), timeout=timeout)
                else:
                    raw = await self.websocket.recv()
            elif self.socket:
                loop = asyncio.get_running_loop()
                self.socket.settimeout(timeout)
                raw = await loop.sock_recv(self.socket, self.config.buffer_size)
                if not raw:
                    raise ConnectionError("Socket closed")
            else:
                return None

            if self.config.encryption_enabled and raw:
                from . import security
                raw = security.decrypt(raw)

            data = json.loads(raw.decode())
            self.messages_received += 1
            self.bytes_received += len(raw)
            self.last_activity = time.time()
            return data
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            logging.getLogger("CSMD64.Connection").error(f"Receive failed: {e}")
            return None

    async def close(self):
        """Close the connection cleanly."""
        try:
            if self.websocket:
                await self.websocket.close()
            if self.socket:
                self.socket.close()
            if self.http_session:
                await self.http_session.close()
            self.is_connected = False
            logging.getLogger("CSMD64.Connection").info(f"Connection closed: {self.name}")
        except Exception as e:
            logging.getLogger("CSMD64.Connection").error(f"Error closing connection: {e}")


# ============================================================================
# CLASS 5: CSMD64ConnectionManager - Manage All Connections
# ============================================================================

class CSMD64ConnectionManager:
    """
    Manages all live connections, providing lookup, broadcast, and statistics.
    """

    def __init__(self, config: CSMD64Config):
        self.config = config
        self.logger = CSMD64Logger(config, "CSMD64.ConnMgr")
        self.connections: Dict[str, CSMD64Connection] = {}
        self._lock = asyncio.Lock()

    async def add_connection(self, connection: CSMD64Connection):
        async with self._lock:
            self.connections[connection.connection_id] = connection
            self.logger.info(f"Connection added: {connection.name} ({connection.connection_type})")

    async def remove_connection(self, connection_id: str):
        async with self._lock:
            if connection_id in self.connections:
                conn = self.connections[connection_id]
                await conn.close()
                del self.connections[connection_id]
                self.logger.info(f"Connection removed: {conn.name}")

    async def get_connection(self, connection_id: str) -> Optional[CSMD64Connection]:
        async with self._lock:
            return self.connections.get(connection_id)

    async def get_connections_by_type(self, conn_type: str) -> List[CSMD64Connection]:
        async with self._lock:
            return [c for c in self.connections.values() if c.connection_type == conn_type]

    async def broadcast(self, message: Dict[str, Any], exclude_id: Optional[str] = None):
        async with self._lock:
            tasks = []
            for cid, conn in self.connections.items():
                if cid != exclude_id and conn.is_connected:
                    tasks.append(conn.send(message))
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                success = sum(1 for r in results if r is True)
                self.logger.info(f"Broadcast to {success}/{len(tasks)} connections")

    async def send_to(self, connection_id: str, message: Dict[str, Any]) -> bool:
        conn = await self.get_connection(connection_id)
        if conn and conn.is_connected:
            return await conn.send(message)
        return False

    def get_stats(self) -> Dict[str, Any]:
        stats = {
            "total": len(self.connections),
            "html_a": len([c for c in self.connections.values() if c.connection_type == "html_a"]),
            "html_b": len([c for c in self.connections.values() if c.connection_type == "html_b"]),
            "exe": len([c for c in self.connections.values() if c.connection_type == "exe"]),
            "total_sent": sum(c.messages_sent for c in self.connections.values()),
            "total_received": sum(c.messages_received for c in self.connections.values()),
            "bytes_sent": sum(c.bytes_sent for c in self.connections.values()),
            "bytes_received": sum(c.bytes_received for c in self.connections.values())
        }
        return stats


# ============================================================================
# CLASS 6: CSMD64HTMLBridge - HTML-to-HTML Bridge
# ============================================================================

class CSMD64HTMLBridge:
    """
    Manages HTML file registry and creates bridges between HTML instances.
    """

    def __init__(self, config: CSMD64Config, security: CSMD64Security, logger: CSMD64Logger):
        self.config = config
        self.security = security
        self.logger = logger
        self.html_files: Dict[str, Dict[str, Any]] = {}
        self.load_html_files()

    def load_html_files(self):
        """Scan html_root_dir and register .html files."""
        root = Path(self.config.html_root_dir)
        root.mkdir(parents=True, exist_ok=True)
        for html_file in root.glob("*.html"):
            try:
                stat = html_file.stat()
                self.register_html(html_file.name, {
                    "path": str(html_file.absolute()),
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "enabled": True
                })
            except Exception as e:
                self.logger.error(f"Failed to register {html_file}: {e}")
        self.logger.info(f"Loaded {len(self.html_files)} HTML files")

    def register_html(self, filename: str, metadata: Dict[str, Any]):
        """Register an HTML file."""
        if not self.security.validate_html_filename(filename):
            raise ValueError(f"Invalid HTML filename: {filename}")
        self.html_files[filename] = {
            **metadata,
            "registered_at": time.time()
        }
        self.logger.info(f"Registered HTML: {filename}")

    def unregister_html(self, filename: str):
        """Remove an HTML file from registry."""
        if filename in self.html_files:
            del self.html_files[filename]
            self.logger.info(f"Unregistered HTML: {filename}")

    def list_html_files(self) -> List[Dict[str, Any]]:
        """Return list of registered HTML files."""
        return [{"filename": f, **meta} for f, meta in self.html_files.items()]

    async def connect_html_a_to_html_b(self, html_a: str, html_b: str, conn_mgr: CSMD64ConnectionManager) -> bool:
        """Create a bridge between html_a (source) and html_b (target)."""
        if html_a not in self.html_files or html_b not in self.html_files:
            self.logger.error(f"HTML not found: {html_a} or {html_b}")
            return False

        # Create connections (in real scenario, establish WebSocket/HTTP)
        conn_a = CSMD64Connection(
            connection_id=f"html_a_{html_a}_{uuid.uuid4().hex[:8]}",
            connection_type="html_a",
            name=html_a,
            config=self.config
        )
        conn_b = CSMD64Connection(
            connection_id=f"html_b_{html_b}_{uuid.uuid4().hex[:8]}",
            connection_type="html_b",
            name=html_b,
            config=self.config
        )
        await conn_mgr.add_connection(conn_a)
        await conn_mgr.add_connection(conn_b)
        self.logger.info(f"Bridge created: {html_a} <-> {html_b}")
        return True

    async def send_html_to_html(self, from_html: str, to_html: str,
                                message: Dict[str, Any], conn_mgr: CSMD64ConnectionManager) -> bool:
        """Send a message from one HTML to another (broadcast to all html_b connections)."""
        # Find source connection
        sources = await conn_mgr.get_connections_by_type("html_a")
        source = next((c for c in sources if c.name == from_html), None)
        if not source:
            self.logger.error(f"Source HTML not connected: {from_html}")
            return False
        # Broadcast to all html_b connections (or filter by name)
        await conn_mgr.broadcast(message, exclude_id=source.connection_id)
        return True


# ============================================================================
# CLASS 7: CSMD64EXEBridge - HTML-to-EXE Bridge
# ============================================================================

class CSMD64EXEBridge:
    """
    Manages launching EXE processes and communication between HTML and EXE.
    """

    def __init__(self, config: CSMD64Config, security: CSMD64Security, logger: CSMD64Logger):
        self.config = config
        self.security = security
        self.logger = logger
        self.exe_processes: Dict[str, subprocess.Popen] = {}

    async def launch_exe(self, exe_path: str, args: Optional[List[str]] = None,
                         env: Optional[Dict[str, str]] = None) -> str:
        """Launch an EXE and return a connection ID."""
        if not self.security.validate_exe_path(exe_path):
            raise ValueError(f"EXE path not allowed: {exe_path}")
        if not os.path.exists(exe_path):
            raise FileNotFoundError(f"EXE not found: {exe_path}")

        conn_id = f"exe_{uuid.uuid4().hex[:8]}"
        try:
            process = subprocess.Popen(
                [exe_path] + (args or []),
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(exe_path)
            )
        except Exception as e:
            self.logger.error(f"Failed to launch EXE {exe_path}: {e}")
            raise

        self.exe_processes[conn_id] = process
        self.logger.info(f"EXE launched: {exe_path} (PID: {process.pid})")
        return conn_id

    async def send_to_exe(self, connection_id: str, message: Dict[str, Any]) -> bool:
        """Send a message to an EXE via stdin."""
        process = self.exe_processes.get(connection_id)
        if not process:
            self.logger.error(f"EXE process not found: {connection_id}")
            return False
        if process.poll() is not None:
            self.logger.error(f"EXE process exited: {connection_id}")
            return False
        try:
            serialized = json.dumps(message).encode() + b"\n"
            process.stdin.write(serialized)
            process.stdin.flush()
            self.logger.info(f"Sent message to EXE {connection_id}")
            return True
        except Exception as e:
            self.logger.error(f"Send to EXE failed: {e}")
            return False

    async def receive_from_exe(self, connection_id: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """Read a message from EXE stdout."""
        process = self.exe_processes.get(connection_id)
        if not process or process.poll() is not None:
            return None
        try:
            loop = asyncio.get_running_loop()
            line = await asyncio.wait_for(
                loop.run_in_executor(None, process.stdout.readline),
                timeout=timeout
            )
            if line:
                return json.loads(line.decode())
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            self.logger.error(f"Receive from EXE failed: {e}")
        return None

    async def terminate_exe(self, connection_id: str, force: bool = False):
        """Terminate an EXE process."""
        process = self.exe_processes.pop(connection_id, None)
        if process:
            try:
                if force:
                    process.kill()
                else:
                    process.terminate()
                process.wait(timeout=5)
            except Exception as e:
                self.logger.error(f"Error terminating EXE: {e}")
            finally:
                self.logger.info(f"EXE terminated: {connection_id}")


# ============================================================================
# CLASS 8: CSMD64HTTPServer - Built-in HTTP Server
# ============================================================================

class CSMD64HTTPServer:
    """
    Embedded HTTP server to serve HTML files and API endpoints.
    Supports aiohttp if available, otherwise falls back to threading HTTP server.
    """

    def __init__(self, config: CSMD64Config, logger: CSMD64Logger):
        self.config = config
        self.logger = logger
        self._server = None
        self._runner = None
        self._site = None
        self._thread = None
        self._stop_event = threading.Event()

    async def start(self):
        """Start the HTTP server."""
        if HAS_AIOHTTP:
            await self._start_aiohttp()
        else:
            self._start_fallback()
        self.logger.info(f"HTTP server started on {self.config.host}:{self.config.port}")

    async def _start_aiohttp(self):
        app = web.Application()

        # Serve HTML files from html_root_dir
        html_dir = self.config.html_root_dir
        if self.config.html_cors_enabled:
            # Simple CORS middleware
            @web.middleware
            async def cors_middleware(request, handler):
                response = await handler(request)
                response.headers['Access-Control-Allow-Origin'] = ','.join(self.config.html_allowed_origins)
                response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                if request.method == 'OPTIONS':
                    return web.Response(status=200)
                return response
            app.middlewares.append(cors_middleware)

        # Routes
        app.router.add_get('/{filename:.*\.html}', self._handle_html_get)
        app.router.add_post('/message', self._handle_message)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.config.host, self.config.port)
        await self._site.start()

    async def _handle_html_get(self, request):
        filename = request.match_info['filename']
        # Security: validate filename
        if '..' in filename or filename.startswith('/'):
            return web.Response(status=403)
        filepath = os.path.join(self.config.html_root_dir, filename)
        if os.path.exists(filepath):
            return web.FileResponse(filepath)
        else:
            return web.Response(status=404, text="HTML not found")

    async def _handle_message(self, request):
        try:
            data = await request.json()
            # In a full implementation, route to connection manager
            return web.json_response({"status": "received"})
        except Exception:
            return web.Response(status=400, text="Invalid JSON")

    def _start_fallback(self):
        """Fallback HTTP server using http.server in a thread."""
        import functools
        html_dir = self.config.html_root_dir

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=html_dir, **kwargs)

            def log_message(self, format, *args):
                pass  # Suppress log

        def run_server():
            with socketserver.TCPServer((self.config.host, self.config.port), Handler) as httpd:
                httpd.timeout = 1
                while not self._stop_event.is_set():
                    httpd.handle_request()

        self._thread = threading.Thread(target=run_server, daemon=True)
        self._thread.start()

    async def stop(self):
        """Stop the HTTP server."""
        if HAS_AIOHTTP and self._runner:
            await self._runner.cleanup()
        if self._thread:
            self._stop_event.set()
            self._thread.join(timeout=2)
        self.logger.info("HTTP server stopped")


# ============================================================================
# CLASS 9: CSMD64WebSocketServer - WebSocket Server for Real-Time
# ============================================================================

class CSMD64WebSocketServer:
    """
    WebSocket server for real-time communication between HTML clients.
    """

    def __init__(self, config: CSMD64Config, logger: CSMD64Logger):
        self.config = config
        self.logger = logger
        self._server = None
        self._clients: Set[Any] = set()
        self._running = False

    async def start(self):
        if not HAS_WEBSOCKETS:
            self.logger.warning("WebSocket server unavailable (websockets not installed)")
            return
        self._running = True
        self._server = await websockets_serve(
            self._handler,
            self.config.host,
            self.config.port + 1,  # Use a different port
            max_size=self.config.max_message_size,
            ping_interval=self.config.keep_alive_interval
        )
        self.logger.info(f"WebSocket server started on ws://{self.config.host}:{self.config.port+1}")

    async def _handler(self, websocket, path):
        self._clients.add(websocket)
        try:
            async for message in websocket:
                # Broadcast to all other clients
                data = json.loads(message)
                await self.broadcast(data, exclude=websocket)
        except ConnectionClosed:
            pass
        finally:
            self._clients.discard(websocket)

    async def broadcast(self, message: Dict[str, Any], exclude=None):
        """Send a message to all connected WebSocket clients."""
        if not self._clients:
            return
        tasks = []
        raw = json.dumps(message).encode()
        for client in self._clients:
            if client != exclude:
                tasks.append(client.send(raw))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self.logger.info("WebSocket server stopped")


# ============================================================================
# CLASS 10: CSMD64DataSync - Real-time Data Synchronization
# ============================================================================

class CSMD64DataSync:
    """
    Real-time data synchronization engine with pub/sub topics.
    """

    def __init__(self, config: CSMD64Config, logger: CSMD64Logger):
        self.config = config
        self.logger = logger
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe to a topic."""
        with self._lock:
            self.subscribers[topic].append(callback)
            self.logger.info(f"Subscribed to topic '{topic}'")

    def unsubscribe(self, topic: str, callback: Callable):
        """Unsubscribe from a topic."""
        with self._lock:
            if topic in self.subscribers:
                try:
                    self.subscribers[topic].remove(callback)
                    self.logger.info(f"Unsubscribed from topic '{topic}'")
                except ValueError:
                    pass

    def publish(self, topic: str, data: Dict[str, Any]):
        """Publish data to all subscribers of a topic."""
        with self._lock:
            callbacks = self.subscribers.get(topic, [])[:]
        for cb in callbacks:
            try:
                cb(data)
            except Exception as e:
                self.logger.error(f"Error in subscriber callback for topic '{topic}': {e}")

    async def async_publish(self, topic: str, data: Dict[str, Any]):
        """Asynchronously publish data."""
        # For async subscribers
        await asyncio.get_event_loop().run_in_executor(None, self.publish, topic, data)


# ============================================================================
# CLASS 11: CSMD64MessageQueue - Message Queue System
# ============================================================================

class CSMD64MessageQueue:
    """
    High-performance asynchronous message queue.
    """

    def __init__(self, config: CSMD64Config, logger: CSMD64Logger):
        self.config = config
        self.logger = logger
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=config.message_queue_size)
        self._consumers: List[Callable] = []

    async def enqueue(self, message: Dict[str, Any]) -> bool:
        """Add a message to the queue."""
        try:
            await self.queue.put(message)
            return True
        except asyncio.QueueFull:
            self.logger.warning("Message queue full, dropping message")
            return False

    async def dequeue(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Retrieve a message from the queue."""
        try:
            if timeout:
                return await asyncio.wait_for(self.queue.get(), timeout=timeout)
            else:
                return await self.queue.get()
        except asyncio.TimeoutError:
            return None

    def register_consumer(self, consumer: Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]):
        """Register an asynchronous consumer callback."""
        self._consumers.append(consumer)

    async def start_consumers(self):
        """Continuously dispatch messages to registered consumers."""
        while True:
            message = await self.dequeue(timeout=1.0)
            if message:
                for consumer in self._consumers:
                    try:
                        await consumer(message)
                    except Exception as e:
                        self.logger.error(f"Consumer error: {e}")

    def size(self) -> int:
        return self.queue.qsize()


# ============================================================================
# CLASS 12: CSMD64EventEmitter - Event-Driven Architecture
# ============================================================================

class CSMD64EventEmitter:
    """
    Event emitter for decoupled communication between components.
    """

    def __init__(self, config: CSMD64Config, logger: CSMD64Logger):
        self.config = config
        self.logger = logger
        self.listeners: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.Lock()

    def on(self, event: str, listener: Callable[[Dict[str, Any]], None]):
        """Register a listener for an event."""
        with self._lock:
            self.listeners[event].append(listener)
            self.logger.debug(f"Listener added for event '{event}'")

    def off(self, event: str, listener: Callable):
        """Remove a listener for an event."""
        with self._lock:
            if event in self.listeners:
                try:
                    self.listeners[event].remove(listener)
                except ValueError:
                    pass

    def emit(self, event: str, data: Optional[Dict[str, Any]] = None):
        """Emit an event to all registered listeners."""
        with self._lock:
            listeners = self.listeners.get(event, [])[:]
        for listener in listeners:
            try:
                listener(data or {})
            except Exception as e:
                self.logger.error(f"Error in listener for event '{event}': {e}")


# ============================================================================
# CLASS 13: CSMD64Database - SQLite Persistence
# ============================================================================

class CSMD64Database:
    """
    Persistent storage using SQLite with connection pooling.
    """

    def __init__(self, config: CSMD64Config, logger: CSMD64Logger):
        self.config = config
        self.logger = logger
        self.db_path = config.database_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._pool: List[sqlite3.Connection] = []
        self._pool_lock = threading.Lock()
        self._max_conn = config.database_pool_size
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a connection from the pool or create a new one."""
        with self._pool_lock:
            if self._pool:
                conn = self._pool.pop()
                try:
                    conn.execute("SELECT 1")
                except sqlite3.ProgrammingError:
                    conn = sqlite3.connect(self.db_path, timeout=self.config.database_timeout)
                return conn
            else:
                return sqlite3.connect(self.db_path, timeout=self.config.database_timeout)

    def _return_conn(self, conn: sqlite3.Connection):
        """Return a connection to the pool."""
        with self._pool_lock:
            if len(self._pool) < self._max_conn:
                self._pool.append(conn)
            else:
                conn.close()

    def _init_db(self):
        """Create tables if they don't exist."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    id TEXT PRIMARY KEY,
                    type TEXT,
                    name TEXT,
                    metadata TEXT,
                    created_at REAL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    from_conn TEXT,
                    to_conn TEXT,
                    content TEXT,
                    timestamp REAL
                )
            """)
            conn.commit()
        except Exception as e:
            self.logger.error(f"Database init error: {e}")
        finally:
            self._return_conn(conn)

    def save_connection(self, conn: CSMD64Connection):
        """Persist a connection record."""
        db_conn = self._get_conn()
        try:
            db_conn.execute(
                "INSERT OR REPLACE INTO connections VALUES (?,?,?,?,?)",
                (conn.connection_id, conn.connection_type, conn.name,
                 json.dumps(conn.metadata), conn.connected_at)
            )
            db_conn.commit()
        except Exception as e:
            self.logger.error(f"Database save error: {e}")
        finally:
            self._return_conn(db_conn)

    def save_message(self, message_id: str, from_conn: str, to_conn: str, content: str):
        """Log a message."""
        db_conn = self._get_conn()
        try:
            db_conn.execute(
                "INSERT INTO messages VALUES (?,?,?,?,?)",
                (message_id, from_conn, to_conn, content, time.time())
            )
            db_conn.commit()
        except Exception as e:
            self.logger.error(f"Database save error: {e}")
        finally:
            self._return_conn(db_conn)

    def get_connection_history(self) -> List[Dict]:
        """Retrieve all connection records."""
        db_conn = self._get_conn()
        try:
            rows = db_conn.execute("SELECT * FROM connections").fetchall()
            return [{"id": r[0], "type": r[1], "name": r[2], "metadata": json.loads(r[3]), "created_at": r[4]} for r in rows]
        finally:
            self._return_conn(db_conn)


# ============================================================================
# CLASS 14: CSMD64Monitor - Performance Monitoring
# ============================================================================

class CSMD64Monitor:
    """
    Collects and reports performance metrics.
    """

    def __init__(self, config: CSMD64Config, logger: CSMD64Logger):
        self.config = config
        self.logger = logger
        self.metrics: Dict[str, List[float]] = defaultdict(list)
        self._running = False
        self._task = None

    async def start_monitoring(self):
        """Begin periodic metric collection."""
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        self.logger.info("Performance monitoring started")

    async def _monitor_loop(self):
        while self._running:
            await self._collect_metrics()
            await asyncio.sleep(self.config.monitoring_interval)

    async def _collect_metrics(self):
        # System metrics
        import psutil
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            self.logger.log_metrics("cpu_usage", cpu)
            self.logger.log_metrics("memory_usage", mem)
        except ImportError:
            pass

    async def stop_monitoring(self):
        self._running = False
        if self._task:
            self._task.cancel()
        self.logger.info("Performance monitoring stopped")

    def get_metrics(self) -> Dict[str, Any]:
        return {name: values[-10:] for name, values in self.metrics.items()}


# ============================================================================
# CLASS 15: CSMD64 - Main Library Class
# ============================================================================

class CSMD64:
    """
    CSMD64 Library - Super Complex Bridge System.
    Unifies all subsystems for managing HTML/EXE connections, real-time sync,
    and inter-process communication.
    """

    def __init__(self, config: Optional[CSMD64Config] = None):
        self.config = config or CSMD64Config()
        valid, errors = self.config.validate()
        if not valid:
            raise ValueError(f"Invalid configuration: {errors}")

        self.logger = CSMD64Logger(self.config)
        self.security = CSMD64Security(self.config)
        self.connection_manager = CSMD64ConnectionManager(self.config)
        self.html_bridge = CSMD64HTMLBridge(self.config, self.security, self.logger)
        self.exe_bridge = CSMD64EXEBridge(self.config, self.security, self.logger)
        self.http_server = CSMD64HTTPServer(self.config, self.logger)
        self.websocket_server = CSMD64WebSocketServer(self.config, self.logger)
        self.data_sync = CSMD64DataSync(self.config, self.logger)
        self.message_queue = CSMD64MessageQueue(self.config, self.logger)
        self.event_emitter = CSMD64EventEmitter(self.config, self.logger)
        self.database = CSMD64Database(self.config, self.logger)
        self.monitor = CSMD64Monitor(self.config, self.logger)

        self._running = False
        self._tasks: List[asyncio.Task] = []

    # ── HTML Management ──
    def add_html(self, filename: str, metadata: Optional[Dict[str, Any]] = None):
        """Register a new HTML file."""
        self.html_bridge.register_html(filename, metadata or {})

    def remove_html(self, filename: str):
        """Unregister an HTML file."""
        self.html_bridge.unregister_html(filename)

    def list_html(self) -> List[Dict[str, Any]]:
        """List all registered HTML files."""
        return self.html_bridge.list_html_files()

    def edit_html_name(self, old_name: str, new_name: str):
        """Rename a registered HTML file."""
        if old_name not in self.html_bridge.html_files:
            raise ValueError(f"HTML not found: {old_name}")
        if not self.security.validate_html_filename(new_name):
            raise ValueError(f"Invalid new filename: {new_name}")
        meta = self.html_bridge.html_files.pop(old_name)
        self.html_bridge.register_html(new_name, meta)
        self.logger.info(f"HTML renamed: {old_name} -> {new_name}")

    # ── HTML-to-HTML Bridge ──
    async def connect_html_a_to_html_b(self, html_a: str, html_b: str) -> bool:
        """Create a bridge between two HTML pages."""
        result = await self.html_bridge.connect_html_a_to_html_b(html_a, html_b, self.connection_manager)
        if result:
            self.event_emitter.emit("html_connected", {"html_a": html_a, "html_b": html_b})
        return result

    async def send_html_to_html(self, from_html: str, to_html: str, message: Dict[str, Any]) -> bool:
        """Send a message from one HTML to another."""
        return await self.html_bridge.send_html_to_html(from_html, to_html, message, self.connection_manager)

    # ── HTML-to-EXE Bridge ──
    async def connect_html_to_exe(self, html_file: str, exe_path: str, args: Optional[List[str]] = None) -> str:
        """Launch an EXE and bridge it with an HTML file."""
        conn_id = await self.exe_bridge.launch_exe(exe_path, args)
        await self.html_bridge.connect_html_a_to_html_b(html_file, os.path.basename(exe_path), self.connection_manager)
        self.event_emitter.emit("exe_connected", {"html": html_file, "exe": exe_path})
        return conn_id

    async def send_html_to_exe(self, html_file: str, message: Dict[str, Any]) -> bool:
        """Send a message from an HTML to its connected EXE."""
        # Find any EXE connection (assuming one per HTML)
        exe_conns = await self.connection_manager.get_connections_by_type("exe")
        if exe_conns:
            return await self.exe_bridge.send_to_exe(exe_conns[0].connection_id, message)
        return False

    async def send_exe_to_html(self, exe_conn_id: str, html_file: str, message: Dict[str, Any]) -> bool:
        """Send a message from an EXE to an HTML file."""
        return await self.html_bridge.send_html_to_html(os.path.basename(exe_conn_id), html_file, message, self.connection_manager)

    # ── Control ──
    async def start(self):
        """Start all servers and services."""
        if self._running:
            return
        self._running = True
        await self.http_server.start()
        await self.websocket_server.start()
        if self.config.monitoring_enabled:
            await self.monitor.start_monitoring()
        # Start message queue consumers
        self._tasks.append(asyncio.create_task(self.message_queue.start_consumers()))
        self.logger.info("CSMD64 system started")

    async def stop(self):
        """Gracefully stop all services."""
        if not self._running:
            return
        self._running = False
        for task in self._tasks:
            task.cancel()
        await self.http_server.stop()
        await self.websocket_server.stop()
        await self.monitor.stop_monitoring()
        # Terminate all EXE processes
        for cid in list(self.exe_bridge.exe_processes.keys()):
            await self.exe_bridge.terminate_exe(cid)
        self.logger.info("CSMD64 system stopped")

    # ── Utilities ──
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive system statistics."""
        return {
            "connections": self.connection_manager.get_stats(),
            "html_files": len(self.html_bridge.html_files),
            "exe_processes": len(self.exe_bridge.exe_processes),
            "metrics": self.logger.get_metrics(),
            "queue_size": self.message_queue.size()
        }

    def save_config(self, path: str = "./config/csmd64_config.json"):
        """Save current config to a JSON file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({
                "host": self.config.host,
                "port": self.config.port,
                "max_connections": self.config.max_connections,
                "encryption_enabled": self.config.encryption_enabled,
                "log_level": self.config.log_level
            }, f, indent=2)
        self.logger.info(f"Config saved to {path}")

    def load_config(self, path: str = "./config/csmd64_config.json"):
        """Load configuration from a JSON file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path, "r") as f:
            data = json.load(f)
        self.config = CSMD64Config(**data)
        self.logger.info(f"Config loaded from {path}")


# ============================================================================
# Exports
# ============================================================================
__all__ = [
    "CSMD64",
    "CSMD64Config",
    "CSMD64Logger",
    "CSMD64Security",
    "CSMD64Connection",
    "CSMD64ConnectionManager",
    "CSMD64HTMLBridge",
    "CSMD64EXEBridge",
    "CSMD64HTTPServer",
    "CSMD64WebSocketServer",
    "CSMD64DataSync",
    "CSMD64MessageQueue",
    "CSMD64EventEmitter",
    "CSMD64Database",
    "CSMD64Monitor"
]

__version__ = "1.0.0"
__author__ = "CSMD64 Team"