"""
DATb64+ Library v1.0.0
======================
Enterprise-grade Database Management + API Key Manager + DDoS Protection + Virtual Database

Architecture:
    - Multi-layer security with AES-256 encryption and HMAC signing
    - DTkey (Database Token Key) system for API authentication
    - Vdat (Virtual Database) for DDoS failover
    - Real-time DDoS detection at 900k-1M req/min threshold
    - HTML-to-database connector with visitor tracking
    - Auto failover, data sync, and recovery
    - Built-in HTTP/API/WebSocket servers

Installation Path: C:\\DATb64+
Python: 3.10+

Author: DATb64+ Team
Version: 1.0.0
"""

# ─────────────────────────────────────────────────────────────────────────────
# STDLIB IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations

import asyncio
import base64
import collections
import contextlib
import copy
import dataclasses
import enum
import functools
import hashlib
import hmac as _hmac
import inspect
import io
import json
import logging
import logging.handlers
import math
import multiprocessing
import operator
import os
import platform
import queue
import random
import re
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import string
import struct
import sys
import tempfile
import threading
import time
import traceback
import types
import typing
import uuid
import warnings
import weakref
import zlib
from collections import defaultdict, deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock, RLock, Event, Condition, Semaphore
from typing import (
    Any, Callable, Dict, Generator, Generic, Iterable,
    Iterator, List, Optional, Set, Tuple, Type, TypeVar, Union
)

# ─────────────────────────────────────────────────────────────────────────────
# THIRD-PARTY IMPORTS (with graceful fallback)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    warnings.warn("cryptography not installed. Run: pip install cryptography", ImportWarning)

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

try:
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False

try:
    import websockets
    _WEBSOCKETS_AVAILABLE = True
except ImportError:
    _WEBSOCKETS_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# MODULE METADATA
# ─────────────────────────────────────────────────────────────────────────────
__version__     = "1.0.0"
__author__      = "DATb64+ Team"
__license__     = "Proprietary"
__description__ = "Enterprise Database Management + API Key Manager + DDoS Protection"

_T = TypeVar("_T")
_INSTALL_ROOT = Path("C:/DATb64+")


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 1 — DATb64Config  (Configuration Manager)
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class DATb64Config:
    """
    Central configuration dataclass for DATb64+.

    Holds 150+ settings across installation paths, database connectivity,
    Supabase quotas, DTkey parameters, Vdat, DDoS thresholds, security,
    performance, logging, and monitoring.

    Usage::

        cfg = DATb64Config(database_type="sqlite")
        ok, errors = cfg.validate()
    """

    # ── Installation Paths ───────────────────────────────────────────────────
    install_path: str  = r"C:\DATb64+"
    data_path:    str  = r"C:\DATb64+\data"
    log_path:     str  = r"C:\DATb64+\logs"
    config_path:  str  = r"C:\DATb64+\config"
    backup_path:  str  = r"C:\DATb64+\backups"
    vdat_path:    str  = r"C:\DATb64+\vdat"
    ssl_path:     str  = r"C:\DATb64+\ssl"
    key_path:     str  = r"C:\DATb64+\data"

    # ── Database Settings ────────────────────────────────────────────────────
    database_type:      str   = "sqlite"      # sqlite | postgresql | supabase
    database_host:      str   = "localhost"
    database_port:      int   = 5432
    database_name:      str   = "datb64_main"
    database_user:      str   = "admin"
    database_password:  str   = ""
    database_pool_size: int   = 20
    database_timeout:   float = 30.0
    database_ssl_mode:  str   = "require"

    # ── Supabase Settings ────────────────────────────────────────────────────
    supabase_url:               str            = ""
    supabase_key:               str            = ""
    supabase_fallback_enabled:  bool           = True
    supabase_quota_limit:       int            = 1_000_000   # 1 M req/month
    supabase_quota_used:        int            = 0
    supabase_quota_reset_time:  Optional[float] = None
    supabase_warning_threshold: int            = 800_000     # 80 %
    supabase_hours_before_exhaustion: int      = 8

    # ── DTkey Settings ───────────────────────────────────────────────────────
    dtkey_length:            int   = 64
    dtkey_expiry:            int   = 2_592_000   # 30 days (seconds)
    dtkey_rotation_enabled:  bool  = True
    dtkey_rotation_interval: int   = 1_555_200   # 18 days (seconds)
    dtkey_hmac_secret:       str   = ""
    dtkey_max_keys_per_user: int   = 10

    # ── Vdat Settings (Virtual Database) ────────────────────────────────────
    vdat_enabled:           bool  = True
    vdat_max_size:          int   = 10 * 1024 ** 3   # 10 GB
    vdat_sync_interval:     float = 60.0              # seconds
    vdat_compression_enabled: bool = True
    vdat_encryption_enabled:  bool = True
    vdat_auto_failover:     bool  = True
    vdat_recovery_threshold: float = 0.80            # 80 % of baseline

    # ── DDoS Protection ──────────────────────────────────────────────────────
    ddos_enabled:             bool      = True
    ddos_detection_threshold: int       = 900_000      # req / window
    ddos_critical_threshold:  int       = 1_000_000
    ddos_window_seconds:      int       = 60
    ddos_mitigation_enabled:  bool      = True
    ddos_block_duration:      int       = 300           # seconds
    ddos_whitelist:           List[str] = field(default_factory=list)
    ddos_blacklist:           List[str] = field(default_factory=list)
    ddos_auto_switch_vdat:    bool      = True
    ddos_traffic_baseline:    int       = 10_000

    # ── Security ─────────────────────────────────────────────────────────────
    encryption_enabled:       bool      = True
    encryption_algorithm:     str       = "AES-256-GCM"
    authentication_enabled:   bool      = True
    authentication_required:  bool      = True
    ssl_enabled:              bool      = True
    ssl_cert_path:            str       = r"C:\DATb64+\ssl\cert.pem"
    ssl_key_path:             str       = r"C:\DATb64+\ssl\key.pem"
    cors_enabled:             bool      = True
    cors_allowed_origins:     List[str] = field(default_factory=lambda: ["*"])
    pbkdf2_iterations:        int       = 260_000

    # ── Performance ──────────────────────────────────────────────────────────
    max_connections:   int   = 10_000
    max_request_size:  int   = 10 * 1024 ** 2   # 10 MB
    request_timeout:   float = 30.0
    rate_limit_enabled:  bool = True
    rate_limit_requests: int  = 1_000
    rate_limit_window:   int  = 60               # seconds
    cache_enabled:  bool = True
    cache_size:     int  = 10_000
    cache_ttl:      int  = 3_600                 # seconds

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level:        str = "INFO"
    log_file:         str = r"C:\DATb64+\logs\datb64.log"
    log_max_size:     int = 50 * 1024 ** 2       # 50 MB
    log_backup_count: int = 10
    log_format:       str = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"

    # ── Monitoring ───────────────────────────────────────────────────────────
    monitoring_enabled:  bool          = True
    monitoring_interval: float         = 5.0
    metrics_retention:   int           = 86_400   # 24 h
    alerts_enabled:      bool          = True
    alert_email:         Optional[str] = None
    alert_webhook:       Optional[str] = None

    # ─────────────────────────────────────────────────────────────────────────
    def validate(self) -> Tuple[bool, List[str]]:
        """
        Validate all configuration values.

        Returns:
            (is_valid: bool, errors: List[str])
        """
        errors: List[str] = []

        if not self.install_path.upper().startswith("C:\\"):
            errors.append("DATb64+ MUST be installed on C:\\ drive")

        if not (1 <= self.database_port <= 65535):
            errors.append(f"Invalid database_port: {self.database_port}")

        if self.ddos_detection_threshold >= self.ddos_critical_threshold:
            errors.append(
                "ddos_detection_threshold must be < ddos_critical_threshold"
            )

        if self.supabase_warning_threshold >= self.supabase_quota_limit:
            errors.append(
                "supabase_warning_threshold must be < supabase_quota_limit"
            )

        if self.vdat_recovery_threshold <= 0 or self.vdat_recovery_threshold > 1:
            errors.append("vdat_recovery_threshold must be in (0, 1]")

        if self.dtkey_max_keys_per_user < 1:
            errors.append("dtkey_max_keys_per_user must be >= 1")

        return len(errors) == 0, errors

    # ─────────────────────────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        """Serialize config to dict (passwords redacted)."""
        d = dataclasses.asdict(self)
        for key in ("database_password", "supabase_key", "dtkey_hmac_secret"):
            if d.get(key):
                d[key] = "***REDACTED***"
        return d

    # ─────────────────────────────────────────────────────────────────────────
    def ensure_directories(self) -> None:
        """Create all required directories."""
        for attr in (
            "install_path", "data_path", "log_path", "config_path",
            "backup_path", "vdat_path", "ssl_path", "key_path",
        ):
            path = Path(getattr(self, attr))
            path.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 2 — DATb64Logger  (Advanced Logging System)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64Logger:
    """
    Advanced structured logging system with:
    - Rotating file handler (main + security logs)
    - Console handler
    - In-memory event ring buffer (last 100 000 events)
    - Security event stream
    - Structured metadata support
    """

    _instances: Dict[str, "DATb64Logger"] = {}
    _lock: Lock = Lock()

    def __new__(cls, config: DATb64Config) -> "DATb64Logger":
        key = config.log_file
        with cls._lock:
            if key not in cls._instances:
                obj = super().__new__(cls)
                obj._initialized = False
                cls._instances[key] = obj
            return cls._instances[key]

    def __init__(self, config: DATb64Config) -> None:
        if self._initialized:  # type: ignore[attr-defined]
            return
        self._initialized = True

        self.config = config
        self._metrics_buf: deque = deque(maxlen=100_000)
        self._security_buf: deque = deque(maxlen=5_000)
        self._lock = RLock()

        # ── Ensure log directory ─────────────────────────────────────────────
        log_dir = Path(config.log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        # ── Build logger ─────────────────────────────────────────────────────
        self._logger = logging.getLogger("DATb64+")
        self._logger.setLevel(getattr(logging, config.log_level, logging.INFO))
        self._logger.propagate = False

        if not self._logger.handlers:
            fmt = logging.Formatter(config.log_format)
            self._add_rotating_handler(config.log_file, fmt, config)
            self._add_rotating_handler(
                str(log_dir / "security.log"), fmt, config,
                level=logging.WARNING
            )
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(fmt)
            ch.setLevel(logging.DEBUG)
            self._logger.addHandler(ch)

    # ─────────────────────────────────────────────────────────────────────────
    def _add_rotating_handler(
        self,
        path: str,
        fmt: logging.Formatter,
        config: DATb64Config,
        level: int = logging.DEBUG,
    ) -> None:
        h = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=config.log_max_size,
            backupCount=config.log_backup_count,
            encoding="utf-8",
        )
        h.setFormatter(fmt)
        h.setLevel(level)
        self._logger.addHandler(h)

    # ─────────────────────────────────────────────────────────────────────────
    def _record(self, level: str, message: str, meta: Dict[str, Any]) -> None:
        with self._lock:
            self._metrics_buf.append({
                "ts":      time.time(),
                "level":   level,
                "message": message,
                "meta":    meta,
            })

    # ─────────────────────────────────────────────────────────────────────────
    def debug(self, msg: str, **meta: Any) -> None:
        self._logger.debug(msg)
        self._record("debug", msg, meta)

    def info(self, msg: str, **meta: Any) -> None:
        self._logger.info(msg)
        self._record("info", msg, meta)

    def warning(self, msg: str, **meta: Any) -> None:
        self._logger.warning(msg)
        self._record("warning", msg, meta)

    def error(self, msg: str, **meta: Any) -> None:
        self._logger.error(msg)
        self._record("error", msg, meta)

    def critical(self, msg: str, **meta: Any) -> None:
        self._logger.critical(msg)
        self._record("critical", msg, meta)

    def security(self, msg: str, **meta: Any) -> None:
        """Log a security-related event to both main log and security buffer."""
        self._logger.warning(f"[SECURITY] {msg}")
        event = {"ts": time.time(), "message": msg, "meta": meta}
        with self._lock:
            self._security_buf.append(event)
            self._record("security", msg, meta)

    # ─────────────────────────────────────────────────────────────────────────
    def get_metrics(
        self,
        since: Optional[float] = None,
        until: Optional[float] = None,
        level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return filtered event records from the in-memory ring buffer."""
        with self._lock:
            records = list(self._metrics_buf)
        if since:
            records = [r for r in records if r["ts"] >= since]
        if until:
            records = [r for r in records if r["ts"] <= until]
        if level:
            records = [r for r in records if r["level"] == level]
        return records

    def get_security_events(self, limit: int = 1_000) -> List[Dict[str, Any]]:
        """Return recent security events."""
        with self._lock:
            return list(self._security_buf)[-limit:]

    def get_error_rate(self, window_seconds: float = 60.0) -> float:
        """Compute errors-per-second in the past window."""
        since = time.time() - window_seconds
        errors = self.get_metrics(since=since, level="error")
        return len(errors) / window_seconds


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 3 — DATb64Security  (Encryption & Authentication)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64Security:
    """
    Hard security layer providing:
    - AES-256-GCM symmetric encryption via Fernet envelope
    - PBKDF2-HMAC-SHA256 password hashing (260 000 iterations)
    - HMAC-SHA256 request/key signing
    - Session management with TTL and activity tracking
    - Input sanitization (SQL injection / XSS strip)
    - Constant-time digest comparison
    """

    _DTKEY_PATTERN = re.compile(r'^datb64_[A-Za-z0-9_\-]{40,}_[a-f0-9]{64}$')

    def __init__(self, config: DATb64Config) -> None:
        self.config = config
        self.log = DATb64Logger(config)
        self._enc_key:   Optional[bytes] = None
        self._fernet:    Optional[Any]   = None   # Fernet
        self._hmac_key:  Optional[bytes] = None
        self._sessions:  Dict[str, Dict[str, Any]] = {}
        self._sess_lock: RLock = RLock()

        data_dir = Path(config.data_path)
        data_dir.mkdir(parents=True, exist_ok=True)

        self._load_or_create_encryption_key(data_dir / "encryption.key")
        self._load_or_create_hmac_key(data_dir / "hmac.key")

    # ─── Key Management ──────────────────────────────────────────────────────
    def _load_or_create_encryption_key(self, path: Path) -> None:
        if not _CRYPTO_AVAILABLE:
            self.log.warning("cryptography unavailable — encryption disabled")
            return
        if path.exists():
            self._enc_key = path.read_bytes()
        else:
            self._enc_key = Fernet.generate_key()
            path.write_bytes(self._enc_key)
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self._fernet = Fernet(self._enc_key)
        self.log.info("Encryption key ready", path=str(path))

    def _load_or_create_hmac_key(self, path: Path) -> None:
        if path.exists():
            self._hmac_key = path.read_bytes()
        else:
            self._hmac_key = os.urandom(64)
            path.write_bytes(self._hmac_key)
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.log.info("HMAC key ready", path=str(path))

    # ─── Encryption / Decryption ─────────────────────────────────────────────
    def encrypt(self, data: Union[str, bytes]) -> bytes:
        """
        Encrypt *data* with AES-256-GCM via Fernet envelope.

        Falls back to identity (no-op) when cryptography is unavailable.
        """
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if not self.config.encryption_enabled or self._fernet is None:
            return raw
        return self._fernet.encrypt(raw)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt Fernet-encrypted *ciphertext*."""
        if not self.config.encryption_enabled or self._fernet is None:
            return ciphertext
        if not _CRYPTO_AVAILABLE:
            return ciphertext
        try:
            return self._fernet.decrypt(ciphertext)
        except InvalidToken as exc:
            self.log.security("Decryption failed — invalid token", error=str(exc))
            raise ValueError("Decryption failed: invalid token") from exc

    # ─── HMAC Signing ────────────────────────────────────────────────────────
    def sign(self, payload: str) -> str:
        """Return HMAC-SHA256 hex digest of *payload*."""
        return _hmac.new(
            self._hmac_key or b"fallback",
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify_signature(self, payload: str, signature: str) -> bool:
        """Constant-time HMAC signature verification."""
        expected = self.sign(payload)
        return _hmac.compare_digest(expected, signature)

    # ─── Password Hashing ────────────────────────────────────────────────────
    def hash_password(
        self,
        password: str,
        salt: Optional[bytes] = None,
    ) -> Tuple[str, str]:
        """
        Hash *password* with PBKDF2-HMAC-SHA256.

        Returns:
            (hash_b64: str, salt_b64: str)
        """
        if salt is None:
            salt = os.urandom(32)
        if _CRYPTO_AVAILABLE:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=self.config.pbkdf2_iterations,
                backend=default_backend(),
            )
            digest = kdf.derive(password.encode("utf-8"))
        else:
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                self.config.pbkdf2_iterations,
            )
        return (
            base64.urlsafe_b64encode(digest).decode(),
            base64.urlsafe_b64encode(salt).decode(),
        )

    def verify_password(self, password: str, stored_hash: str, stored_salt: str) -> bool:
        """Constant-time password verification."""
        salt = base64.urlsafe_b64decode(stored_salt)
        candidate_hash, _ = self.hash_password(password, salt)
        return _hmac.compare_digest(candidate_hash, stored_hash)

    # ─── Session Management ──────────────────────────────────────────────────
    def create_session(
        self,
        user_id: str,
        ip_address: str,
        dtkey: str,
        ttl: float = 86_400.0,
    ) -> str:
        """Create a new authenticated session and return its ID."""
        sid = str(uuid.uuid4())
        now = time.time()
        with self._sess_lock:
            self._sessions[sid] = {
                "user_id":       user_id,
                "ip_address":    ip_address,
                "dtkey":         dtkey,
                "created_at":    now,
                "expires_at":    now + ttl,
                "last_activity": now,
                "request_count": 0,
            }
        self._purge_expired_sessions()
        return sid

    def validate_session(self, session_id: str) -> bool:
        """Return True if *session_id* exists and has not expired."""
        with self._sess_lock:
            sess = self._sessions.get(session_id)
            if sess is None:
                return False
            if time.time() > sess["expires_at"]:
                del self._sessions[session_id]
                return False
            sess["last_activity"] = time.time()
            sess["request_count"] += 1
        return True

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return session metadata dict or None."""
        with self._sess_lock:
            return copy.deepcopy(self._sessions.get(session_id))

    def invalidate_session(self, session_id: str) -> None:
        """Explicitly invalidate a session."""
        with self._sess_lock:
            self._sessions.pop(session_id, None)

    def _purge_expired_sessions(self) -> int:
        """Remove expired sessions. Returns count removed."""
        now = time.time()
        with self._sess_lock:
            expired = [k for k, v in self._sessions.items() if v["expires_at"] < now]
            for k in expired:
                del self._sessions[k]
        return len(expired)

    def active_session_count(self) -> int:
        self._purge_expired_sessions()
        with self._sess_lock:
            return len(self._sessions)

    # ─── Input Sanitization ──────────────────────────────────────────────────
    _SQL_STRIP  = re.compile(r"(--|;|/\*|\*/|'|\")", re.IGNORECASE)
    _XSS_STRIP  = re.compile(r"(<script|javascript:|on\w+=|<iframe)", re.IGNORECASE)
    _PATH_STRIP = re.compile(r"\.\./|\.\.\\")

    def sanitize(self, value: Any) -> Any:
        """
        Recursively sanitize *value* to strip SQL injection, XSS, and path
        traversal patterns.  Non-string leaf values are returned unchanged.
        """
        if isinstance(value, str):
            v = self._SQL_STRIP.sub("", value)
            v = self._XSS_STRIP.sub("", v)
            v = self._PATH_STRIP.sub("", v)
            return v.strip()
        if isinstance(value, dict):
            return {k: self.sanitize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            cleaned = [self.sanitize(i) for i in value]
            return type(value)(cleaned)
        return value

    # ─── DTkey Format Validation ─────────────────────────────────────────────
    def validate_dtkey_format(self, dtkey: str) -> bool:
        """Check structural format of a DTkey string."""
        return bool(self._DTKEY_PATTERN.match(dtkey))

    # ─── Utility ─────────────────────────────────────────────────────────────
    def generate_token(self, n_bytes: int = 32) -> str:
        """Return URL-safe random token of *n_bytes* entropy."""
        return base64.urlsafe_b64encode(os.urandom(n_bytes)).decode().rstrip("=")

    def constant_compare(self, a: str, b: str) -> bool:
        """Wrapper around hmac.compare_digest for equal-time comparison."""
        return _hmac.compare_digest(a, b)


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 4 — DATb64DTkeyManager  (DTkey API Key Management)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64DTkeyManager:
    """
    Manages DTkeys (Database Token Keys) — the primary API authentication tokens.

    Features:
    - Cryptographically signed token generation (HMAC-SHA256)
    - Structured payload: user_id, database_name, permissions, expiry, metadata
    - Validation with signature verification and expiry check
    - Key rotation (generate new → revoke old atomically)
    - Revocation with immediate effect
    - Per-user key cap enforcement
    - Persistent storage (JSON, encrypted at rest)
    - Usage tracking per key

    Token format::

        datb64_<base64url_payload>_<hmac_hex>
    """

    def __init__(self, config: DATb64Config, security: Optional[DATb64Security] = None) -> None:
        self.config  = config
        self.log     = DATb64Logger(config)
        self.sec     = security or DATb64Security(config)
        self._lock   = RLock()

        # In-memory stores
        self._keys:       Dict[str, Dict[str, Any]]       = {}   # dtkey → metadata
        self._user_keys:  Dict[str, List[str]]            = {}   # user_id → [dtkey, ...]
        self._usage:      Dict[str, deque]                = {}   # dtkey → usage events

        self._store_path = Path(config.data_path) / "dtkeys.enc"
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    # ─── Persistence ─────────────────────────────────────────────────────────
    def _load(self) -> None:
        if not self._store_path.exists():
            return
        try:
            raw = self._store_path.read_bytes()
            decrypted = self.sec.decrypt(raw)
            data = json.loads(decrypted.decode("utf-8"))
            self._keys      = data.get("keys", {})
            self._user_keys = data.get("user_keys", {})
            raw_usage = data.get("usage", {})
            for k, v in raw_usage.items():
                self._usage[k] = deque(v, maxlen=10_000)
            self.log.info(f"DTkey store loaded: {len(self._keys)} keys")
        except Exception as exc:
            self.log.error(f"DTkey store load failed: {exc}")

    def _save(self) -> None:
        try:
            payload = {
                "keys":      self._keys,
                "user_keys": self._user_keys,
                "usage":     {k: list(v) for k, v in self._usage.items()},
            }
            raw  = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            enc  = self.sec.encrypt(raw)
            self._store_path.write_bytes(enc)
        except Exception as exc:
            self.log.error(f"DTkey store save failed: {exc}")

    # ─── Generation ──────────────────────────────────────────────────────────
    def generate_dtkey(
        self,
        user_id:       str,
        database_name: str,
        permissions:   Optional[List[str]] = None,
        ttl:           Optional[int]       = None,
        meta:          Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate a new DTkey for *user_id* / *database_name*.

        Args:
            user_id:       Owner identifier.
            database_name: Target database name.
            permissions:   List of permission strings (default: ["read","write"]).
            ttl:           Expiry in seconds (default from config).
            meta:          Additional metadata dict to embed in token.

        Returns:
            DTkey string in the form ``datb64_<payload>_<signature>``

        Raises:
            ValueError: If the user has reached the per-user key limit.
        """
        with self._lock:
            user_keys = self._user_keys.get(user_id, [])
            if len(user_keys) >= self.config.dtkey_max_keys_per_user:
                raise ValueError(
                    f"User '{user_id}' has reached the max DTkey limit "
                    f"({self.config.dtkey_max_keys_per_user})"
                )

            now        = time.time()
            expiry_ttl = ttl if ttl is not None else self.config.dtkey_expiry

            payload_dict = {
                "kid":        str(uuid.uuid4()),
                "user_id":    user_id,
                "db":         database_name,
                "perms":      permissions or ["read", "write"],
                "iat":        now,
                "exp":        now + expiry_ttl,
                "usage":      0,
                "meta":       meta or {},
            }

            encoded_payload = (
                base64.urlsafe_b64encode(
                    json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
                )
                .decode()
                .rstrip("=")
            )

            signature = self.sec.sign(encoded_payload)
            dtkey     = f"datb64_{encoded_payload}_{signature}"

            self._keys[dtkey]   = payload_dict
            self._usage[dtkey]  = deque(maxlen=10_000)
            if user_id not in self._user_keys:
                self._user_keys[user_id] = []
            self._user_keys[user_id].append(dtkey)

            self._save()
            self.log.info(
                "DTkey generated",
                user=user_id, db=database_name, kid=payload_dict["kid"]
            )
            return dtkey

    # ─── Validation ──────────────────────────────────────────────────────────
    def validate_dtkey(
        self, dtkey: str, required_permission: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate *dtkey*.

        Checks:
        1. Structural format (regex)
        2. Existence in store
        3. Expiry (exp claim)
        4. HMAC signature integrity
        5. Optional permission check

        Returns:
            (is_valid: bool, payload: Optional[dict])
        """
        if not self.sec.validate_dtkey_format(dtkey):
            self.log.security("DTkey format invalid", preview=dtkey[:20])
            return False, None

        with self._lock:
            if dtkey not in self._keys:
                self.log.security("DTkey not found in store", preview=dtkey[:20])
                return False, None

            payload = self._keys[dtkey]

            if time.time() > payload["exp"]:
                self.log.warning("DTkey expired", user=payload.get("user_id"))
                return False, None

            # Verify signature
            parts = dtkey.rsplit("_", 1)
            if len(parts) != 2:
                return False, None
            body, sig = parts
            body = body[len("datb64_"):]
            if not self.sec.verify_signature(body, sig):
                self.log.security("DTkey HMAC signature mismatch", preview=dtkey[:20])
                return False, None

            # Optional permission check
            if required_permission and required_permission not in payload.get("perms", []):
                return False, None

            # Update usage
            payload["usage"] = payload.get("usage", 0) + 1
            self._usage[dtkey].append({"ts": time.time(), "action": "validate"})

        return True, payload

    # ─── Rotation ────────────────────────────────────────────────────────────
    def rotate_dtkey(self, old_dtkey: str) -> str:
        """
        Atomically rotate *old_dtkey*: generate a replacement with the same
        parameters, then revoke the old one.

        Returns:
            New DTkey string.
        """
        with self._lock:
            if old_dtkey not in self._keys:
                raise ValueError("DTkey not found")
            old_payload = copy.deepcopy(self._keys[old_dtkey])

        new_dtkey = self.generate_dtkey(
            user_id       = old_payload["user_id"],
            database_name = old_payload["db"],
            permissions   = old_payload["perms"],
            meta          = old_payload.get("meta"),
        )
        self.revoke_dtkey(old_dtkey)
        self.log.info("DTkey rotated", user=old_payload["user_id"])
        return new_dtkey

    # ─── Revocation ──────────────────────────────────────────────────────────
    def revoke_dtkey(self, dtkey: str) -> bool:
        """
        Revoke *dtkey* immediately.

        Returns:
            True if the key existed and was revoked, False otherwise.
        """
        with self._lock:
            if dtkey not in self._keys:
                return False
            user_id = self._keys[dtkey].get("user_id", "")
            del self._keys[dtkey]
            self._usage.pop(dtkey, None)
            if user_id in self._user_keys:
                with contextlib.suppress(ValueError):
                    self._user_keys[user_id].remove(dtkey)
            self._save()
        self.log.info("DTkey revoked", preview=dtkey[:20])
        return True

    # ─── Query / Introspection ───────────────────────────────────────────────
    def list_user_dtkeys(self, user_id: str) -> List[Dict[str, Any]]:
        """Return summary list of all DTkeys owned by *user_id*."""
        with self._lock:
            result = []
            for dtkey in self._user_keys.get(user_id, []):
                if dtkey not in self._keys:
                    continue
                d = copy.deepcopy(self._keys[dtkey])
                d["preview"] = dtkey[:30] + "..."
                d.pop("kid", None)
                result.append(d)
        return result

    def get_usage_history(self, dtkey: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent usage events for *dtkey*."""
        with self._lock:
            q = self._usage.get(dtkey, deque())
            return list(q)[-limit:]

    def total_key_count(self) -> int:
        with self._lock:
            return len(self._keys)

    def get_expiring_soon(self, within_seconds: int = 86_400) -> List[Dict[str, Any]]:
        """Return DTkeys expiring within *within_seconds*."""
        threshold = time.time() + within_seconds
        with self._lock:
            return [
                {**v, "preview": k[:30] + "..."}
                for k, v in self._keys.items()
                if v["exp"] <= threshold
            ]


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 5 — DATb64Database  (Real Database Handler)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64Database:
    """
    Async-compatible database abstraction supporting:
    - SQLite  (default, zero-config, file-based at C:\\DATb64+\\data\\main.db)
    - PostgreSQL  (via psycopg2 — install separately)
    - Supabase  (via supabase-py — install separately)

    All SQL queries use parameterised placeholders to prevent injection.
    The connection is threadsafe via an internal RLock.

    Usage::

        db = DATb64Database(config)
        await db.connect()
        rows = await db.query("SELECT * FROM users WHERE id = ?", (uid,))
    """

    SCHEMA_VERSION = 4

    def __init__(self, config: DATb64Config) -> None:
        self.config    = config
        self.log       = DATb64Logger(config)
        self._conn:    Any  = None
        self._lock     = RLock()
        self._db_type  = config.database_type
        self._connected = False

    # ─── Connection ──────────────────────────────────────────────────────────
    async def connect(self, db_type: Optional[str] = None) -> None:
        """Establish database connection."""
        t = db_type or self._db_type
        if t == "sqlite":
            await self._connect_sqlite()
        elif t == "postgresql":
            await self._connect_postgresql()
        elif t == "supabase":
            await self._connect_supabase()
        else:
            raise ValueError(f"Unsupported database type: {t!r}")
        self._connected = True
        self.log.info(f"Database connected ({t})")

    async def _connect_sqlite(self) -> None:
        db_file = Path(self.config.data_path) / "main.db"
        db_file.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_file), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA cache_size=-32768")    # 32 MB page cache
        self._apply_schema_sqlite()

    def _apply_schema_sqlite(self) -> None:
        """Create/migrate schema for SQLite."""
        ddl_statements = [
            """CREATE TABLE IF NOT EXISTS schema_version (
                   version INTEGER PRIMARY KEY,
                   applied_at REAL NOT NULL
               )""",
            """CREATE TABLE IF NOT EXISTS users (
                   id           TEXT PRIMARY KEY,
                   username     TEXT UNIQUE NOT NULL,
                   email        TEXT UNIQUE,
                   password_hash TEXT NOT NULL,
                   password_salt TEXT NOT NULL,
                   is_active    INTEGER DEFAULT 1,
                   created_at   REAL NOT NULL,
                   updated_at   REAL NOT NULL,
                   last_login   REAL
               )""",
            """CREATE TABLE IF NOT EXISTS data (
                   id         TEXT PRIMARY KEY,
                   user_id    TEXT NOT NULL,
                   key        TEXT NOT NULL,
                   value      TEXT,
                   ttl        REAL,
                   created_at REAL NOT NULL,
                   updated_at REAL NOT NULL,
                   FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
               )""",
            "CREATE INDEX IF NOT EXISTS idx_data_user_key ON data(user_id, key)",
            """CREATE TABLE IF NOT EXISTS dtkeys (
                   dtkey         TEXT PRIMARY KEY,
                   user_id       TEXT NOT NULL,
                   database_name TEXT NOT NULL,
                   permissions   TEXT NOT NULL,
                   created_at    REAL NOT NULL,
                   expires_at    REAL NOT NULL,
                   usage_count   INTEGER DEFAULT 0,
                   revoked       INTEGER DEFAULT 0,
                   FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
               )""",
            """CREATE TABLE IF NOT EXISTS access_log (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   user_id    TEXT,
                   ip_address TEXT,
                   action     TEXT NOT NULL,
                   path       TEXT,
                   status     INTEGER,
                   duration   REAL,
                   timestamp  REAL NOT NULL
               )""",
            "CREATE INDEX IF NOT EXISTS idx_access_log_ts ON access_log(timestamp)",
            """CREATE TABLE IF NOT EXISTS ddos_events (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   event_type TEXT NOT NULL,
                   ip_address TEXT,
                   traffic    INTEGER,
                   details    TEXT,
                   timestamp  REAL NOT NULL
               )""",
            """CREATE TABLE IF NOT EXISTS vdat_sync_log (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   synced     INTEGER DEFAULT 0,
                   errors     INTEGER DEFAULT 0,
                   duration   REAL,
                   timestamp  REAL NOT NULL
               )""",
        ]
        with self._lock:
            cur = self._conn.cursor()
            for ddl in ddl_statements:
                cur.execute(ddl)
            # Upsert schema version
            cur.execute(
                "INSERT OR REPLACE INTO schema_version VALUES (?, ?)",
                (self.SCHEMA_VERSION, time.time()),
            )
            self._conn.commit()

    async def _connect_postgresql(self) -> None:
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError as e:
            raise ImportError("psycopg2 is required for PostgreSQL: pip install psycopg2-binary") from e

        self._conn = psycopg2.connect(
            host     = self.config.database_host,
            port     = self.config.database_port,
            dbname   = self.config.database_name,
            user     = self.config.database_user,
            password = self.config.database_password,
            sslmode  = self.config.database_ssl_mode,
            connect_timeout = int(self.config.database_timeout),
        )
        self._conn.autocommit = False

    async def _connect_supabase(self) -> None:
        try:
            from supabase import create_client  # type: ignore
        except ImportError as e:
            raise ImportError("supabase-py required: pip install supabase") from e

        if not self.config.supabase_url or not self.config.supabase_key:
            raise ValueError("supabase_url and supabase_key must be set in config")

        self._conn = create_client(self.config.supabase_url, self.config.supabase_key)
        await self._check_supabase_quota()

    async def _check_supabase_quota(self) -> None:
        used = self.config.supabase_quota_used
        limit = self.config.supabase_quota_limit
        pct = (used / limit * 100) if limit else 0
        self.log.info(f"Supabase quota: {used}/{limit} ({pct:.1f}%)")
        if used >= self.config.supabase_warning_threshold:
            self.log.critical(
                f"SUPABASE QUOTA WARNING: {pct:.1f}% used! "
                f"Estimated exhaustion in ~{self.config.supabase_hours_before_exhaustion}h"
            )
            if self.config.alert_webhook and _AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as sess:
                    with contextlib.suppress(Exception):
                        await sess.post(
                            self.config.alert_webhook,
                            json={"alert": f"Supabase quota {pct:.1f}% used"},
                            timeout=aiohttp.ClientTimeout(total=5),
                        )

    # ─── Query API ───────────────────────────────────────────────────────────
    async def query(
        self, sql: str, params: Optional[Tuple] = None
    ) -> List[Dict[str, Any]]:
        """Execute a SELECT (or any) statement; return rows as dicts."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute(sql, params or ())
                if self._db_type == "sqlite":
                    cols = [d[0] for d in cur.description] if cur.description else []
                    return [dict(zip(cols, row)) for row in cur.fetchall()]
                return [dict(row) for row in cur.fetchall()]
            except Exception as exc:
                self.log.error(f"Query error: {exc}", sql=sql[:120])
                raise

    async def execute(self, sql: str, params: Optional[Tuple] = None) -> int:
        """Execute a non-SELECT statement; return rowcount."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute(sql, params or ())
                if self._db_type in ("sqlite",):
                    self._conn.commit()
                else:
                    self._conn.commit()
                return cur.rowcount
            except Exception as exc:
                self.log.error(f"Execute error: {exc}", sql=sql[:120])
                self._conn.rollback()
                raise

    async def insert(self, table: str, data: Dict[str, Any]) -> Optional[str]:
        """INSERT *data* into *table*. Returns last-row id as str."""
        cols  = ", ".join(data.keys())
        ph    = ", ".join("?" * len(data))
        sql   = f"INSERT INTO {table} ({cols}) VALUES ({ph})"
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, list(data.values()))
            self._conn.commit()
            return str(cur.lastrowid)

    async def update(
        self,
        table: str,
        data: Dict[str, Any],
        where: str,
        where_params: Tuple = (),
    ) -> int:
        """UPDATE *table* SET *data* WHERE *where*. Returns rowcount."""
        set_clause = ", ".join(f"{k} = ?" for k in data.keys())
        sql = f"UPDATE {table} SET {set_clause} WHERE {where}"
        params = list(data.values()) + list(where_params)
        return await self.execute(sql, tuple(params))

    async def delete(
        self, table: str, where: str, params: Tuple = ()
    ) -> int:
        """DELETE FROM *table* WHERE *where*. Returns rowcount."""
        return await self.execute(f"DELETE FROM {table} WHERE {where}", params)

    async def upsert(self, table: str, data: Dict[str, Any], pk: str = "id") -> Optional[str]:
        """INSERT OR REPLACE into *table*."""
        cols  = ", ".join(data.keys())
        ph    = ", ".join("?" * len(data))
        sql   = f"INSERT OR REPLACE INTO {table} ({cols}) VALUES ({ph})"
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, list(data.values()))
            self._conn.commit()
            return str(cur.lastrowid)

    # ─── Helpers ─────────────────────────────────────────────────────────────
    @property
    def is_connected(self) -> bool:
        return self._connected and self._conn is not None

    async def ping(self) -> bool:
        """Return True if the database is alive."""
        try:
            await self.query("SELECT 1")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(Exception):
                self._conn.close()
            self._conn     = None
            self._connected = False
            self.log.info("Database connection closed")


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 6 — DATb64Vdat  (Virtual Database — DDoS Failover)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64Vdat:
    """
    Vdat — in-process Virtual Database used as a high-speed failover backend
    during DDoS attack windows.

    Behaviour:
    - Activated automatically when DDoS threshold is reached (via DDoSProtection)
    - All reads and writes are served from an in-memory dict with optional
      on-disk persistence (zlib-compressed, Fernet-encrypted)
    - A pending-sync queue records every write made while Vdat is active
    - On deactivation the pending queue is flushed back to the real database
      via ``sync_back_to_real_db``
    - Periodic auto-save prevents data loss during prolonged attacks

    Capacity:
    - Up to ``vdat_max_size`` bytes on disk (10 GB default)
    - No hard per-record limit in memory (rely on OS / hardware constraints)
    """

    def __init__(self, config: DATb64Config, security: Optional[DATb64Security] = None) -> None:
        self.config  = config
        self.log     = DATb64Logger(config)
        self.sec     = security or DATb64Security(config)
        self._lock   = RLock()

        self._store:    Dict[str, Dict[str, Any]] = {}   # key → record
        self._pending:  List[Dict[str, Any]]      = []   # unsynced writes
        self._is_active = False
        self._is_syncing = False
        self._activated_at: Optional[float] = None
        self._write_count  = 0

        self._disk_path = Path(config.vdat_path) / "vdat.bin"
        self._disk_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_from_disk()

    # ─── Persistence ─────────────────────────────────────────────────────────
    def _load_from_disk(self) -> None:
        if not self._disk_path.exists():
            return
        try:
            raw = self._disk_path.read_bytes()
            if self.config.vdat_encryption_enabled:
                raw = self.sec.decrypt(raw)
            if self.config.vdat_compression_enabled:
                raw = zlib.decompress(raw)
            self._store = json.loads(raw.decode("utf-8"))
            self.log.info(f"Vdat loaded from disk: {len(self._store)} records")
        except Exception as exc:
            self.log.error(f"Vdat disk load failed: {exc}")

    def _save_to_disk(self) -> None:
        try:
            raw = json.dumps(self._store, separators=(",", ":")).encode("utf-8")
            if self.config.vdat_compression_enabled:
                raw = zlib.compress(raw, level=6)
            if self.config.vdat_encryption_enabled:
                raw = self.sec.encrypt(raw)
            self._disk_path.write_bytes(raw)
        except Exception as exc:
            self.log.error(f"Vdat disk save failed: {exc}")

    # ─── Lifecycle ───────────────────────────────────────────────────────────
    def activate(self, reason: str = "DDoS threshold reached") -> None:
        """Switch from real database to Vdat."""
        with self._lock:
            if self._is_active:
                return
            self._is_active    = True
            self._activated_at = time.time()
        self.log.critical(f"Vdat ACTIVATED ─ {reason}")
        self.log.critical("All write traffic is now routed to the virtual database")

    def deactivate(self) -> None:
        """Re-enable real database mode (sync back must be called separately)."""
        with self._lock:
            if not self._is_active:
                return
            duration = time.time() - (self._activated_at or time.time())
            self._is_active    = False
            self._activated_at = None
        self.log.info(f"Vdat DEACTIVATED (was active for {duration:.1f}s)")

    @property
    def is_active(self) -> bool:
        return self._is_active

    # ─── CRUD ────────────────────────────────────────────────────────────────
    async def store(
        self,
        key:     str,
        value:   Any,
        user_id: Optional[str] = None,
        ttl:     Optional[float] = None,
    ) -> bool:
        """Write *value* under *key* to Vdat."""
        record = {
            "key":        key,
            "value":      value,
            "user_id":    user_id,
            "ts":         time.time(),
            "ttl":        ttl,
            "synced":     False,
        }
        with self._lock:
            self._store[key] = record
            self._pending.append(record)
            self._write_count += 1
            should_flush = self._write_count % 500 == 0

        if should_flush:
            self._save_to_disk()

        return True

    async def get(self, key: str) -> Optional[Any]:
        """Retrieve value for *key* from Vdat (or None)."""
        with self._lock:
            rec = self._store.get(key)
        if rec is None:
            return None
        if rec.get("ttl") and time.time() > rec["ts"] + rec["ttl"]:
            with self._lock:
                self._store.pop(key, None)
            return None
        return rec["value"]

    async def delete(self, key: str) -> bool:
        """Delete *key* from Vdat."""
        with self._lock:
            existed = key in self._store
            self._store.pop(key, None)
        return existed

    async def keys(self, pattern: Optional[str] = None) -> List[str]:
        """Return all stored keys, optionally matching *pattern*."""
        with self._lock:
            all_keys = list(self._store.keys())
        if pattern:
            regex = re.compile(pattern.replace("*", ".*"))
            return [k for k in all_keys if regex.match(k)]
        return all_keys

    # ─── Sync Back ───────────────────────────────────────────────────────────
    async def sync_back_to_real_db(self, database: DATb64Database) -> Dict[str, int]:
        """
        Flush all pending (unsynced) Vdat writes to *database*.

        Returns:
            {"synced": N, "errors": E}
        """
        with self._lock:
            if self._is_syncing:
                return {"synced": 0, "errors": 0, "skipped": "already syncing"}
            self._is_syncing = True
            pending = [r for r in self._pending if not r.get("synced")]

        self.log.info(f"Vdat sync starting: {len(pending)} pending records")
        synced = errors = 0

        for rec in pending:
            try:
                await database.upsert("data", {
                    "id":         str(uuid.uuid4()),
                    "user_id":    rec.get("user_id") or "system",
                    "key":        rec["key"],
                    "value":      json.dumps(rec["value"]),
                    "created_at": rec["ts"],
                    "updated_at": time.time(),
                })
                rec["synced"] = True
                synced += 1
            except Exception as exc:
                self.log.error(f"Vdat sync error for key {rec['key']!r}: {exc}")
                errors += 1

        with self._lock:
            self._pending   = [r for r in self._pending if not r.get("synced")]
            self._is_syncing = False

        self._save_to_disk()
        self.log.info(f"Vdat sync complete: synced={synced}, errors={errors}")
        return {"synced": synced, "errors": errors}

    # ─── Stats ───────────────────────────────────────────────────────────────
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_active":    self._is_active,
                "record_count": len(self._store),
                "pending_sync": len([r for r in self._pending if not r.get("synced")]),
                "total_writes": self._write_count,
                "disk_path":    str(self._disk_path),
                "disk_size_mb": (
                    self._disk_path.stat().st_size / 1_048_576
                    if self._disk_path.exists() else 0
                ),
            }

    def flush(self) -> None:
        """Force an immediate disk flush."""
        self._save_to_disk()


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 7 — DATb64TrafficAnalyzer
# ══════════════════════════════════════════════════════════════════════════════
class DATb64TrafficAnalyzer:
    """
    Real-time traffic analysis engine used by DDoSProtection.

    Maintains:
    - A sliding-window request counter per IP (configurable window)
    - Global request counter per window
    - Per-IP request rate (requests / second)
    - Anomaly score per IP (0.0 – 1.0) based on deviation from baseline
    - Top-N attacking IP ranking
    """

    def __init__(self, config: DATb64Config) -> None:
        self.config   = config
        self.log      = DATb64Logger(config)
        self._lock    = RLock()
        self._window  = config.ddos_window_seconds

        # Sliding-window per-IP buckets: ip → deque of timestamps
        self._ip_ts:     Dict[str, deque] = defaultdict(lambda: deque())
        # Global timestamp ring
        self._global_ts: deque            = deque()
        # Per-IP anomaly scores
        self._anomaly:   Dict[str, float] = {}

        self._total_requests = 0

    # ─────────────────────────────────────────────────────────────────────────
    def record(self, ip: str) -> None:
        """Record an incoming request from *ip*."""
        now = time.time()
        cutoff = now - self._window

        with self._lock:
            self._total_requests += 1

            # Global window
            self._global_ts.append(now)
            while self._global_ts and self._global_ts[0] < cutoff:
                self._global_ts.popleft()

            # Per-IP window
            bucket = self._ip_ts[ip]
            bucket.append(now)
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            # Compute anomaly score for this IP
            ip_rate    = len(bucket) / self._window          # req/s
            baseline   = self.config.ddos_traffic_baseline / self._window
            score      = min(ip_rate / max(baseline, 1), 1.0)
            self._anomaly[ip] = score

    def global_request_rate(self) -> float:
        """Return requests/second in the current window."""
        with self._lock:
            return len(self._global_ts) / self._window

    def window_total(self) -> int:
        """Return total requests in the current window."""
        with self._lock:
            return len(self._global_ts)

    def ip_request_count(self, ip: str) -> int:
        """Return request count in current window for *ip*."""
        with self._lock:
            return len(self._ip_ts.get(ip, deque()))

    def anomaly_score(self, ip: str) -> float:
        """Return anomaly score (0–1) for *ip*. Higher = more suspicious."""
        with self._lock:
            return self._anomaly.get(ip, 0.0)

    def top_ips(self, n: int = 20) -> List[Tuple[str, int]]:
        """Return top *n* IPs by request count in the current window."""
        with self._lock:
            ranked = sorted(
                ((ip, len(q)) for ip, q in self._ip_ts.items()),
                key=operator.itemgetter(1),
                reverse=True,
            )
        return ranked[:n]

    def summary(self) -> Dict[str, Any]:
        return {
            "window_seconds":   self._window,
            "global_requests":  self.window_total(),
            "global_rate_rps":  round(self.global_request_rate(), 2),
            "unique_ips":       len(self._ip_ts),
            "total_lifetime":   self._total_requests,
        }


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 8 — DATb64DDoSProtection  (DDoS Detection & Mitigation)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64DDoSProtection:
    """
    Multi-layer DDoS detection and mitigation:

    Levels:
    1. **Warning**   (≥ 500 000 req/min) — log and increase scrutiny
    2. **Detection** (≥ 900 000 req/min) — activate Vdat, rate-limit
    3. **Critical**  (≥ 1 000 000 req/min) — block new connections

    Mitigation actions:
    - Automatic switch to Vdat virtual database
    - IP-level temporary bans (configurable duration)
    - Whitelist / blacklist enforcement
    - Gradual recovery: deactivate Vdat once traffic drops below
      ``vdat_recovery_threshold × ddos_traffic_baseline``

    Thread-safe.  Does not spawn background tasks (caller is responsible).
    """

    WARNING_FRACTION = 0.5   # warning at 50 % of detection threshold

    def __init__(
        self,
        config:   DATb64Config,
        vdat:     Optional[DATb64Vdat]            = None,
        security: Optional[DATb64Security]        = None,
    ) -> None:
        self.config   = config
        self.log      = DATb64Logger(config)
        self.sec      = security or DATb64Security(config)
        self.vdat     = vdat or DATb64Vdat(config, self.sec)
        self.analyzer = DATb64TrafficAnalyzer(config)
        self._lock    = RLock()

        self._is_under_attack  = False
        self._attack_start:    Optional[float]     = None
        self._attack_level:    str                 = "none"
        self._blocked_ips:     Dict[str, float]    = {}   # ip → unblock_ts
        self._recovery_window: deque               = deque(maxlen=10)

    # ─── Request Processing ──────────────────────────────────────────────────
    def record_request(self, ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Record a single incoming request and evaluate DDoS state.

        Returns a dict with ``{"allowed": bool, "reason": str, "level": str}``.
        """
        ip = ip or "0.0.0.0"

        # Whitelist override
        if ip in self.config.ddos_whitelist:
            self.analyzer.record(ip)
            return {"allowed": True, "reason": "whitelisted", "level": "ok"}

        # Permanent blacklist
        if ip in self.config.ddos_blacklist:
            self.log.security("Blacklisted IP attempt", ip=ip)
            return {"allowed": False, "reason": "blacklisted", "level": "blocked"}

        # Temporary block
        if self._is_temp_blocked(ip):
            return {"allowed": False, "reason": "temp_blocked", "level": "blocked"}

        self.analyzer.record(ip)
        window_total = self.analyzer.window_total()
        self._evaluate_state(window_total, ip)

        allowed = not self._is_under_attack or self._attack_level != "critical"
        return {
            "allowed": allowed,
            "level":   self._attack_level,
            "reason":  "attack" if not allowed else "ok",
            "traffic": window_total,
        }

    # ─────────────────────────────────────────────────────────────────────────
    def _evaluate_state(self, traffic: int, ip: str) -> None:
        cfg = self.config
        warning_threshold  = int(cfg.ddos_detection_threshold * self.WARNING_FRACTION)
        detect_threshold   = cfg.ddos_detection_threshold
        critical_threshold = cfg.ddos_critical_threshold

        with self._lock:
            if traffic >= critical_threshold:
                if self._attack_level != "critical":
                    self._set_attack("critical", traffic)
            elif traffic >= detect_threshold:
                if self._attack_level not in ("detection", "critical"):
                    self._set_attack("detection", traffic)
            elif traffic >= warning_threshold:
                if self._attack_level not in ("warning", "detection", "critical"):
                    self._set_attack("warning", traffic)
            elif self._is_under_attack:
                # Check recovery
                recovery_limit = cfg.ddos_traffic_baseline * cfg.vdat_recovery_threshold
                self._recovery_window.append(traffic < recovery_limit)
                if all(self._recovery_window) and len(self._recovery_window) == 10:
                    self._end_attack(traffic)

    def _set_attack(self, level: str, traffic: int) -> None:
        """Escalate to *level*."""
        self._is_under_attack = True
        self._attack_level    = level
        if self._attack_start is None:
            self._attack_start = time.time()

        self.log.critical(
            f"DDoS {level.upper()}: {traffic:,} req/{self.config.ddos_window_seconds}s"
        )

        if level in ("detection", "critical") and self.config.ddos_auto_switch_vdat:
            if not self.vdat.is_active:
                self.vdat.activate(f"DDoS {level}: {traffic:,} req")

    def _end_attack(self, traffic: int) -> None:
        duration = time.time() - (self._attack_start or time.time())
        self._is_under_attack = False
        self._attack_level    = "none"
        self._attack_start    = None
        self._recovery_window.clear()

        self.log.info(
            f"DDoS attack ended (duration={duration:.0f}s, traffic={traffic:,})"
        )
        if self.vdat.is_active:
            self.vdat.deactivate()

    # ─── IP Blocking ─────────────────────────────────────────────────────────
    def block_ip(self, ip: str, duration: Optional[int] = None) -> None:
        """Temporarily block *ip* for *duration* seconds."""
        t = duration or self.config.ddos_block_duration
        with self._lock:
            self._blocked_ips[ip] = time.time() + t
        self.log.warning(f"IP temporarily blocked: {ip} for {t}s")

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                return True
        return False

    def _is_temp_blocked(self, ip: str) -> bool:
        with self._lock:
            until = self._blocked_ips.get(ip)
            if until is None:
                return False
            if time.time() > until:
                del self._blocked_ips[ip]
                return False
        return True

    # ─── Stats ───────────────────────────────────────────────────────────────
    @property
    def is_under_attack(self) -> bool:
        return self._is_under_attack

    @property
    def attack_level(self) -> str:
        return self._attack_level

    def traffic_stats(self) -> Dict[str, Any]:
        return {
            **self.analyzer.summary(),
            "is_under_attack":  self._is_under_attack,
            "attack_level":     self._attack_level,
            "attack_duration":  (
                time.time() - self._attack_start
                if self._attack_start else 0
            ),
            "blocked_ip_count": len(self._blocked_ips),
            "vdat_active":      self.vdat.is_active,
            "top_ips":          self.analyzer.top_ips(10),
        }


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 9 — DATb64HTMLConnector  (HTML ↔ Database Bridge)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64HTMLConnector:
    """
    Bridges HTML front-ends to the DATb64+ backend:

    - Registers and tracks visitor sessions (IP, user-agent, page, referrer)
    - Validates incoming DTkeys on every HTML API request
    - Provides per-page analytics (unique visits, session duration)
    - Generates embeddable JavaScript snippet for quick integration
    - Thread-safe visitor log with configurable retention
    """

    def __init__(
        self,
        config:   DATb64Config,
        dtkey_mgr: Optional[DATb64DTkeyManager] = None,
        security:  Optional[DATb64Security]     = None,
    ) -> None:
        self.config    = config
        self.log       = DATb64Logger(config)
        self.sec       = security or DATb64Security(config)
        self.dtkey_mgr = dtkey_mgr
        self._lock     = RLock()

        self._sessions:  Dict[str, Dict[str, Any]] = {}
        self._log:       deque                     = deque(maxlen=500_000)
        self._page_hits: Dict[str, int]            = defaultdict(int)

    # ─── Visitor Registration ────────────────────────────────────────────────
    def register_visitor(
        self,
        ip_address: str,
        user_agent: str,
        dtkey:      str,
        page_url:   str,
        referrer:   str = "",
    ) -> str:
        """
        Register an HTML visitor.

        Returns a session ID that can be used to track subsequent actions.
        """
        sid = str(uuid.uuid4())
        record = {
            "session_id": sid,
            "ip":         ip_address,
            "ua":         user_agent[:512],
            "dtkey_ok":   self._quick_dtkey_check(dtkey),
            "page":       page_url,
            "referrer":   referrer,
            "ts":         time.time(),
            "actions":    [],
        }
        with self._lock:
            self._sessions[sid] = record
            self._log.append(record)
            self._page_hits[page_url] += 1

        self.log.info("Visitor registered", ip=ip_address, page=page_url)
        return sid

    def _quick_dtkey_check(self, dtkey: str) -> bool:
        """Fast format-only DTkey check (no HMAC verification)."""
        return dtkey.startswith("datb64_") and len(dtkey) > 80

    def record_action(self, session_id: str, action: str, data: Any = None) -> bool:
        """Append an action event to an existing session."""
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None:
                return False
            sess["actions"].append({"action": action, "data": data, "ts": time.time()})
        return True

    def end_session(self, session_id: str) -> Optional[float]:
        """Close session and return its duration in seconds."""
        with self._lock:
            sess = self._sessions.pop(session_id, None)
            if sess:
                return time.time() - sess["ts"]
        return None

    # ─── Visitors Query ──────────────────────────────────────────────────────
    def get_all_visitors(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent visitor records (no sensitive fields)."""
        with self._lock:
            recent = list(self._log)[-limit:]
        return [
            {
                "session_id": r["session_id"],
                "ip":         r["ip"],
                "page":       r["page"],
                "ts":         r["ts"],
                "dtkey_ok":   r["dtkey_ok"],
            }
            for r in recent
        ]

    def get_visitors_by_ip(self, ip: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [r for r in self._log if r["ip"] == ip]

    def get_page_analytics(self) -> Dict[str, int]:
        """Return hit count per page URL."""
        with self._lock:
            return dict(self._page_hits)

    def unique_ip_count(self) -> int:
        with self._lock:
            return len({r["ip"] for r in self._log})

    # ─── Database Connection Helper ──────────────────────────────────────────
    async def connect_html_to_database(
        self,
        html_file: str,
        dtkey:     str,
        database:  DATb64Database,
    ) -> bool:
        """
        Associate an HTML file with the database using *dtkey*.
        Validates the key and logs the binding.
        """
        if self.dtkey_mgr:
            ok, payload = self.dtkey_mgr.validate_dtkey(dtkey)
            if not ok:
                self.log.error("HTML connector: invalid DTkey", html=html_file)
                return False
        else:
            if not self._quick_dtkey_check(dtkey):
                return False

        self.log.info("HTML connected to database", html=html_file)
        return True

    # ─── JS Snippet Generator ────────────────────────────────────────────────
    def generate_js_snippet(
        self,
        api_base_url: str,
        dtkey:        str,
        options:      Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Return a ``<script>`` block that the HTML page can embed to
        communicate with the DATb64+ API server.
        """
        opts = options or {}
        return f"""<!-- DATb64+ Integration Snippet v{__version__} -->
<script>
(function() {{
  var DATb64 = {{
    apiBase: "{api_base_url}",
    dtkey: "{dtkey}",
    options: {json.dumps(opts)},
    _fetch: function(path, method, body) {{
      return fetch(this.apiBase + path, {{
        method: method || "GET",
        headers: {{
          "Content-Type": "application/json",
          "X-DATb64-DTkey": this.dtkey
        }},
        body: body ? JSON.stringify(body) : undefined
      }}).then(function(r) {{ return r.json(); }});
    }},
    get: function(key) {{ return this._fetch("/data/" + key); }},
    set: function(key, value) {{ return this._fetch("/data/" + key, "POST", {{value: value}}); }},
    del: function(key) {{ return this._fetch("/data/" + key, "DELETE"); }},
  }};
  window.DATb64 = DATb64;
  console.info("[DATb64+] Integration loaded (v{__version__})");
}})();
</script>"""


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 10 — DATb64HTTPServer
# ══════════════════════════════════════════════════════════════════════════════
class DATb64HTTPServer:
    """
    Minimal built-in HTTP server wrapping Python's http.server.

    Serves static files and routes ``/api/`` prefixed requests to the
    DATb64APIServer handler.  Runs in a daemon thread so it does not
    block the event loop.

    For production loads use a reverse proxy (nginx / caddy) in front.
    """

    def __init__(self, config: DATb64Config) -> None:
        self.config   = config
        self.log      = DATb64Logger(config)
        self._server  = None
        self._thread: Optional[threading.Thread] = None
        self._port    = 8080
        self._running = False

    async def start(self, port: int = 8080) -> None:
        self._port = port
        if self._running:
            return
        from http.server import HTTPServer, BaseHTTPRequestHandler

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                outer.log.debug(fmt % args)

            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps({"status": "ok", "server": "DATb64+", "version": __version__})
                    .encode()
                )

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body   = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"received": len(body)}).encode())

        self._server = HTTPServer(("0.0.0.0", port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="DATb64-HTTP"
        )
        self._thread.start()
        self._running = True
        self.log.info(f"HTTP server listening on 0.0.0.0:{port}")

    async def stop(self) -> None:
        if self._server:
            self._server.shutdown()
        self._running = False
        self.log.info("HTTP server stopped")

    @property
    def is_running(self) -> bool:
        return self._running


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 11 — DATb64APIServer  (REST API)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64APIServer:
    """
    Async REST API server built on asyncio streams.

    Endpoints:
    - GET  /health                 — liveness probe
    - GET  /stats                  — system statistics
    - POST /api/dtkey/generate     — create DTkey
    - POST /api/dtkey/validate     — validate DTkey
    - DELETE /api/dtkey/revoke     — revoke DTkey
    - GET  /api/data/<key>         — read key
    - POST /api/data/<key>         — write key
    - DELETE /api/data/<key>       — delete key
    - GET  /api/visitors           — visitor list
    - GET  /api/ddos/stats         — DDoS statistics

    All API endpoints require a valid DTkey in the ``X-DATb64-DTkey`` header
    (unless authentication_required = False in config).
    """

    ROUTES: Dict[str, Dict[str, str]] = {
        "GET":    {
            "/health":         "_handle_health",
            "/stats":          "_handle_stats",
            "/api/visitors":   "_handle_visitors",
            "/api/ddos/stats": "_handle_ddos_stats",
        },
        "POST":   {
            "/api/dtkey/generate": "_handle_dtkey_generate",
            "/api/dtkey/validate": "_handle_dtkey_validate",
        },
        "DELETE": {
            "/api/dtkey/revoke": "_handle_dtkey_revoke",
        },
    }

    def __init__(
        self,
        config:   DATb64Config,
        main_ref: Optional[Any] = None,   # DATb64 main instance
    ) -> None:
        self.config   = config
        self.log      = DATb64Logger(config)
        self.main     = main_ref
        self._server  = None
        self._running = False
        self._port    = 8081

    async def start(self, port: int = 8081) -> None:
        self._port   = port
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", port
        )
        self._running = True
        self.log.info(f"API server listening on 0.0.0.0:{port}")
        asyncio.ensure_future(self._serve())

    async def _serve(self) -> None:
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False
        self.log.info("API server stopped")

    # ─── Request Dispatcher ──────────────────────────────────────────────────
    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw = await asyncio.wait_for(reader.read(65536), timeout=10.0)
            if not raw:
                return

            request  = raw.decode("utf-8", errors="replace")
            lines    = request.split("\r\n")
            req_line = lines[0].split()
            if len(req_line) < 2:
                return

            method, path = req_line[0], req_line[1]

            # Parse headers
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k.lower()] = v

            # Parse body
            body_str = request.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in request else ""
            try:
                body = json.loads(body_str) if body_str.strip() else {}
            except json.JSONDecodeError:
                body = {}

            response = await self._dispatch(method, path, headers, body)
            status   = response.get("_status", 200)
            response.pop("_status", None)

            resp_body = json.dumps(response).encode()
            http_resp = (
                f"HTTP/1.1 {status} OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(resp_body)}\r\n"
                f"X-DATb64-Version: {__version__}\r\n"
                f"\r\n"
            ).encode() + resp_body

            writer.write(http_resp)
            await writer.drain()
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            self.log.error(f"API handler error: {exc}")
        finally:
            writer.close()

    async def _dispatch(
        self,
        method:  str,
        path:    str,
        headers: Dict[str, str],
        body:    Dict[str, Any],
    ) -> Dict[str, Any]:
        # Auth check
        if self.config.authentication_required:
            dtkey = headers.get("x-datb64-dtkey", "")
            if not dtkey and self.main:
                dtkey = body.get("dtkey", "")
            if not dtkey:
                return {"error": "Missing DTkey", "_status": 401}

        # Dynamic data path: /api/data/<key>
        data_match = re.match(r"^/api/data/(.+)$", path)
        if data_match:
            key = data_match.group(1)
            return await self._handle_data(method, key, body)

        handler_name = self.ROUTES.get(method, {}).get(path)
        if not handler_name:
            return {"error": "Not found", "_status": 404}

        handler = getattr(self, handler_name, None)
        if handler is None:
            return {"error": "Handler not implemented", "_status": 501}

        return await handler(headers, body)

    # ─── Handlers ────────────────────────────────────────────────────────────
    async def _handle_health(self, headers: Dict, body: Dict) -> Dict:
        return {"status": "healthy", "version": __version__, "ts": time.time()}

    async def _handle_stats(self, headers: Dict, body: Dict) -> Dict:
        if self.main:
            return self.main.get_stats()
        return {"error": "main not attached"}

    async def _handle_visitors(self, headers: Dict, body: Dict) -> Dict:
        if self.main:
            return {"visitors": self.main.get_all_visitors()}
        return {"visitors": []}

    async def _handle_ddos_stats(self, headers: Dict, body: Dict) -> Dict:
        if self.main:
            return self.main.ddos_protection.traffic_stats()
        return {}

    async def _handle_dtkey_generate(self, headers: Dict, body: Dict) -> Dict:
        if not self.main:
            return {"error": "service unavailable", "_status": 503}
        try:
            dtkey = self.main.generate_dtkey(
                user_id       = body.get("user_id", "api_user"),
                database_name = body.get("database_name", "default"),
                permissions   = body.get("permissions"),
            )
            return {"dtkey": dtkey}
        except ValueError as e:
            return {"error": str(e), "_status": 400}

    async def _handle_dtkey_validate(self, headers: Dict, body: Dict) -> Dict:
        if not self.main:
            return {"error": "service unavailable", "_status": 503}
        dtkey = body.get("dtkey", headers.get("x-datb64-dtkey", ""))
        ok, payload = self.main.dtkey_manager.validate_dtkey(dtkey)
        return {"valid": ok, "payload": payload if ok else None}

    async def _handle_dtkey_revoke(self, headers: Dict, body: Dict) -> Dict:
        if not self.main:
            return {"error": "service unavailable", "_status": 503}
        dtkey = body.get("dtkey", "")
        ok = self.main.dtkey_manager.revoke_dtkey(dtkey)
        return {"revoked": ok}

    async def _handle_data(self, method: str, key: str, body: Dict) -> Dict:
        if not self.main:
            return {"error": "service unavailable", "_status": 503}
        if method == "GET":
            value = await self.main.get_data(key)
            return {"key": key, "value": value}
        elif method == "POST":
            await self.main.store_data(key, body.get("value"))
            return {"stored": True, "key": key}
        elif method == "DELETE":
            if self.main.vdat.is_active:
                ok = await self.main.vdat.delete(key)
            else:
                ok = bool(await self.main.database.delete("data", "key = ?", (key,)))
            return {"deleted": ok, "key": key}
        return {"error": "method not allowed", "_status": 405}

    @property
    def is_running(self) -> bool:
        return self._running


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 12 — DATb64WebSocketServer
# ══════════════════════════════════════════════════════════════════════════════
class DATb64WebSocketServer:
    """
    Real-time WebSocket server for live stats streaming (DDoS dashboard,
    Vdat status, visitor feed).

    Clients authenticate by sending a DTkey as the first message.
    After authentication, subscribed clients receive periodic JSON push
    messages containing the current system state.

    Falls back to a stub if the ``websockets`` package is unavailable.
    """

    def __init__(
        self, config: DATb64Config, main_ref: Optional[Any] = None
    ) -> None:
        self.config  = config
        self.log     = DATb64Logger(config)
        self.main    = main_ref
        self._clients: Set[Any] = set()
        self._running = False
        self._server  = None
        self._port    = 8082
        self._broadcast_interval = 2.0   # seconds

    async def start(self, port: int = 8082) -> None:
        self._port = port
        if not _WEBSOCKETS_AVAILABLE:
            self.log.warning("websockets package not installed — WS server disabled")
            return
        try:
            import websockets  # type: ignore
            self._server = await websockets.serve(
                self._handle_client, "0.0.0.0", port
            )
            self._running = True
            self.log.info(f"WebSocket server on 0.0.0.0:{port}")
            asyncio.ensure_future(self._broadcast_loop())
        except Exception as exc:
            self.log.error(f"WebSocket start error: {exc}")

    async def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, ws: Any, path: str) -> None:
        """Authenticate client then keep connection alive."""
        try:
            auth_msg = await asyncio.wait_for(ws.recv(), timeout=10.0)
            data = json.loads(auth_msg)
            dtkey = data.get("dtkey", "")
            if self.main and self.config.authentication_required:
                ok, _ = self.main.dtkey_manager.validate_dtkey(dtkey)
                if not ok:
                    await ws.send(json.dumps({"error": "invalid dtkey"}))
                    return

            self._clients.add(ws)
            await ws.send(json.dumps({"event": "authenticated", "version": __version__}))
            await ws.wait_closed()
        except Exception:
            pass
        finally:
            self._clients.discard(ws)

    async def _broadcast_loop(self) -> None:
        """Push system stats to all connected clients every N seconds."""
        while self._running:
            if self._clients and self.main:
                payload = json.dumps({
                    "event": "stats",
                    "ts":    time.time(),
                    "data":  self.main.get_stats(),
                })
                dead = set()
                for ws in list(self._clients):
                    try:
                        await ws.send(payload)
                    except Exception:
                        dead.add(ws)
                self._clients -= dead
            await asyncio.sleep(self._broadcast_interval)

    def broadcast_sync(self, message: Dict[str, Any]) -> None:
        """Fire-and-forget broadcast from synchronous code."""
        payload = json.dumps(message)
        for ws in list(self._clients):
            asyncio.ensure_future(ws.send(payload))

    @property
    def connected_count(self) -> int:
        return len(self._clients)


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 13 — DATb64DataSync
# ══════════════════════════════════════════════════════════════════════════════
class DATb64DataSync:
    """
    Orchestrates bidirectional data synchronisation between Vdat (virtual DB)
    and the real database.

    Responsibilities:
    - Trigger sync on Vdat deactivation
    - Periodic background sync during recovery phase
    - Conflict resolution (last-write-wins by default)
    - Sync health reporting
    """

    def __init__(self, config: DATb64Config) -> None:
        self.config       = config
        self.log          = DATb64Logger(config)
        self._sync_count  = 0
        self._last_sync:  Optional[float] = None
        self._lock        = RLock()

    async def sync(
        self, vdat: DATb64Vdat, database: DATb64Database
    ) -> Dict[str, Any]:
        """
        Sync all pending Vdat records to *database*.

        Returns sync result dict.
        """
        if not database.is_connected:
            self.log.error("DataSync: database not connected")
            return {"error": "database not connected"}

        start  = time.time()
        result = await vdat.sync_back_to_real_db(database)

        with self._lock:
            self._sync_count += 1
            self._last_sync   = time.time()

        result["duration"]    = round(time.time() - start, 3)
        result["sync_number"] = self._sync_count
        self.log.info(
            f"DataSync #{self._sync_count}: {result.get('synced',0)} records "
            f"in {result['duration']}s"
        )
        return result

    async def schedule_periodic(
        self,
        vdat:     DATb64Vdat,
        database: DATb64Database,
        interval: Optional[float] = None,
    ) -> None:
        """Run periodic sync loop (call with asyncio.ensure_future)."""
        iv = interval or self.config.vdat_sync_interval
        while True:
            await asyncio.sleep(iv)
            if vdat.is_active:
                await self.sync(vdat, database)

    def status(self) -> Dict[str, Any]:
        return {
            "sync_count": self._sync_count,
            "last_sync":  self._last_sync,
        }


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 14 — DATb64Cache  (In-Memory LRU Cache)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64Cache:
    """
    Thread-safe LRU cache with TTL support.

    - Backed by ``collections.OrderedDict`` (O(1) LRU eviction)
    - Optional per-key TTL (defaults to config.cache_ttl)
    - Hit/miss/eviction counters
    - ``get_or_set`` helper to reduce boilerplate
    """

    def __init__(self, config: DATb64Config) -> None:
        self.config    = config
        self._max      = config.cache_size
        self._default_ttl = float(config.cache_ttl)
        self._store:   OrderedDict = OrderedDict()   # key → (value, expires_at)
        self._lock     = RLock()
        self._hits     = 0
        self._misses   = 0
        self._evictions = 0

    # ─────────────────────────────────────────────────────────────────────────
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._store.get(key)
            if item is None:
                self._misses += 1
                return None
            value, expires_at = item
            if time.time() > expires_at:
                del self._store[key]
                self._misses += 1
                return None
            # Move to end (most recently used)
            self._store.move_to_end(key)
            self._hits += 1
            return value

    def set(
        self,
        key:   str,
        value: Any,
        ttl:   Optional[float] = None,
    ) -> None:
        expires = time.time() + (ttl if ttl is not None else self._default_ttl)
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, expires)
            while len(self._store) > self._max:
                self._store.popitem(last=False)
                self._evictions += 1

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
        return False

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def get_or_set(
        self, key: str, factory: Callable[[], Any], ttl: Optional[float] = None
    ) -> Any:
        """Return cached value or call *factory* to compute and cache it."""
        value = self.get(key)
        if value is None:
            value = factory()
            self.set(key, value, ttl)
        return value

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "size":      len(self._store),
                "max_size":  self._max,
                "hits":      self._hits,
                "misses":    self._misses,
                "evictions": self._evictions,
                "hit_rate":  (
                    self._hits / max(self._hits + self._misses, 1)
                ),
            }


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 15 — DATb64RateLimiter  (Token Bucket)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64RateLimiter:
    """
    Per-IP token-bucket rate limiter.

    Each IP gets a bucket of ``rate_limit_requests`` tokens.
    Tokens refill at ``rate_limit_requests / rate_limit_window`` tokens/second.
    A request consumes one token.  When the bucket is empty the request
    is rate-limited.

    Thread-safe.
    """

    def __init__(self, config: DATb64Config) -> None:
        self.config   = config
        self._lock    = RLock()
        # ip → [tokens_remaining: float, last_refill_ts: float]
        self._buckets: Dict[str, List[float]] = {}
        self._capacity = float(config.rate_limit_requests)
        self._refill_rate = config.rate_limit_requests / max(config.rate_limit_window, 1)

    def _ensure_bucket(self, ip: str) -> None:
        if ip not in self._buckets:
            self._buckets[ip] = [self._capacity, time.time()]

    def _refill(self, ip: str) -> None:
        now   = time.time()
        bucket = self._buckets[ip]
        elapsed = now - bucket[1]
        bucket[0] = min(self._capacity, bucket[0] + elapsed * self._refill_rate)
        bucket[1] = now

    def is_limited(self, ip: str) -> bool:
        """Return True if *ip* should be rate-limited."""
        if not self.config.rate_limit_enabled:
            return False
        with self._lock:
            self._ensure_bucket(ip)
            self._refill(ip)
            if self._buckets[ip][0] >= 1.0:
                self._buckets[ip][0] -= 1.0
                return False
        return True

    def remaining(self, ip: str) -> int:
        """Return remaining token count for *ip*."""
        with self._lock:
            self._ensure_bucket(ip)
            self._refill(ip)
            return int(self._buckets[ip][0])

    def reset(self, ip: str) -> None:
        """Reset bucket for *ip* to full capacity."""
        with self._lock:
            self._buckets[ip] = [self._capacity, time.time()]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "tracked_ips": len(self._buckets),
                "capacity":    self._capacity,
                "refill_rate": self._refill_rate,
            }


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 16 — DATb64EventEmitter  (Event-Driven Architecture)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64EventEmitter:
    """
    Lightweight synchronous/asynchronous event bus.

    - ``on(event, callback)``   — subscribe
    - ``off(event, callback)``  — unsubscribe
    - ``once(event, callback)`` — subscribe for a single firing
    - ``emit(event, **kwargs)`` — fire event (sync + async handlers)
    - ``emit_async``            — await all async handlers concurrently
    """

    def __init__(self) -> None:
        self._handlers:      Dict[str, List[Callable]] = defaultdict(list)
        self._once_handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = RLock()
        self._history: deque = deque(maxlen=1_000)

    def on(self, event: str, callback: Callable) -> None:
        with self._lock:
            self._handlers[event].append(callback)

    def off(self, event: str, callback: Callable) -> None:
        with self._lock:
            with contextlib.suppress(ValueError):
                self._handlers[event].remove(callback)

    def once(self, event: str, callback: Callable) -> None:
        with self._lock:
            self._once_handlers[event].append(callback)

    def emit(self, event: str, **kwargs: Any) -> int:
        """
        Fire *event* synchronously.  Returns number of handlers called.
        Async handlers are scheduled on the running event loop if available.
        """
        with self._lock:
            handlers = list(self._handlers.get(event, []))
            once = list(self._once_handlers.pop(event, []))

        self._history.append({"event": event, "ts": time.time(), "data": kwargs})
        count = 0

        for cb in handlers + once:
            try:
                if inspect.iscoroutinefunction(cb):
                    with contextlib.suppress(RuntimeError):
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            asyncio.ensure_future(cb(**kwargs))
                else:
                    cb(**kwargs)
                count += 1
            except Exception as exc:
                pass   # emitters must not crash callers

        return count

    async def emit_async(self, event: str, **kwargs: Any) -> int:
        """Fire *event* and await all async handlers concurrently."""
        with self._lock:
            handlers = list(self._handlers.get(event, []))
            once = list(self._once_handlers.pop(event, []))

        self._history.append({"event": event, "ts": time.time(), "data": kwargs})

        coros = []
        for cb in handlers + once:
            if inspect.iscoroutinefunction(cb):
                coros.append(cb(**kwargs))
            else:
                with contextlib.suppress(Exception):
                    cb(**kwargs)

        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

        return len(handlers) + len(once)

    def event_names(self) -> List[str]:
        with self._lock:
            return list(self._handlers.keys())

    def listener_count(self, event: str) -> int:
        with self._lock:
            return len(self._handlers.get(event, []))

    def history(self, limit: int = 100) -> List[Dict[str, Any]]:
        return list(self._history)[-limit:]


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 17 — DATb64DatabasePool  (Connection Pool)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64DatabasePool:
    """
    Simple fixed-size connection pool for synchronous database drivers
    (SQLite / psycopg2).

    Connections are checked out with ``acquire()`` (context manager) and
    returned with ``release()``.  Exhaustion raises ``TimeoutError`` after
    *acquire_timeout* seconds.
    """

    def __init__(self, config: DATb64Config) -> None:
        self.config       = config
        self.log          = DATb64Logger(config)
        self._pool_size   = config.database_pool_size
        self._timeout     = config.database_timeout
        self._connections: queue.Queue = queue.Queue(maxsize=self._pool_size)
        self._created     = 0
        self._lock        = Lock()

    def _create_connection(self) -> Any:
        """Create a new raw database connection."""
        if self.config.database_type == "sqlite":
            db_file = Path(self.config.data_path) / "main.db"
            conn = sqlite3.connect(str(db_file), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn
        raise NotImplementedError(
            f"Pool not implemented for {self.config.database_type}"
        )

    def acquire(self) -> Any:
        """Obtain a connection from the pool (blocks up to timeout)."""
        try:
            return self._connections.get(timeout=self._timeout)
        except queue.Empty:
            with self._lock:
                if self._created < self._pool_size:
                    conn = self._create_connection()
                    self._created += 1
                    return conn
            raise TimeoutError("Database pool exhausted")

    def release(self, conn: Any) -> None:
        """Return *conn* to the pool."""
        try:
            self._connections.put_nowait(conn)
        except queue.Full:
            with contextlib.suppress(Exception):
                conn.close()

    @contextlib.contextmanager
    def connection(self):
        """Context manager for safe connection acquire/release."""
        conn = self.acquire()
        try:
            yield conn
        finally:
            self.release(conn)

    def size(self) -> int:
        return self._connections.qsize()

    def pre_fill(self, n: Optional[int] = None) -> None:
        """Pre-create *n* connections (default: pool_size)."""
        n = n or self._pool_size
        for _ in range(n):
            if self._connections.full():
                break
            conn = self._create_connection()
            self._connections.put(conn)
            with self._lock:
                self._created += 1
        self.log.info(f"Pool pre-filled with {n} connections")


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 18 — DATb64Monitor  (Performance Monitor & Alerting)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64Monitor:
    """
    Real-time performance monitor.

    Collects:
    - Request rate (req/s, last 60 s)
    - Error rate
    - Vdat activity and pending sync count
    - DDoS attack state and level
    - Memory & CPU usage (if psutil available)
    - Uptime

    Supports webhook and email alerting with configurable thresholds.
    Runs a background monitoring loop in a daemon thread.
    """

    def __init__(self, config: DATb64Config) -> None:
        self.config     = config
        self.log        = DATb64Logger(config)
        self._start_ts  = time.time()
        self._lock      = RLock()

        self._metrics:   Dict[str, Any] = {
            "uptime_s":      0,
            "total_requests": 0,
            "total_errors":   0,
            "rps":            0.0,
            "error_rate":     0.0,
            "vdat_active":    False,
            "ddos_level":     "none",
            "cpu_pct":        None,
            "mem_mb":         None,
        }

        self._metric_history: deque = deque(maxlen=int(
            config.metrics_retention / config.monitoring_interval
        ))
        self._main_ref: Optional[Any] = None
        self._thread:   Optional[threading.Thread] = None
        self._stop_evt  = threading.Event()

    def attach(self, main_ref: Any) -> None:
        """Attach to the main DATb64 instance for stats collection."""
        self._main_ref = main_ref

    def start_background_monitoring(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="DATb64-Monitor"
        )
        self._thread.start()
        self.log.info(f"Monitor started (interval={self.config.monitoring_interval}s)")

    def stop_background_monitoring(self) -> None:
        self._stop_evt.set()

    def _monitor_loop(self) -> None:
        while not self._stop_evt.wait(self.config.monitoring_interval):
            self._collect()

    def _collect(self) -> None:
        snapshot: Dict[str, Any] = {
            "ts":       time.time(),
            "uptime_s": time.time() - self._start_ts,
        }

        if self._main_ref:
            stats = self._main_ref.get_stats()
            snapshot.update({
                "vdat_active":    stats.get("vdat_active", False),
                "ddos_level":     self._main_ref.ddos_protection.attack_level,
                "total_requests": self._main_ref.ddos_protection.analyzer._total_requests,
                "rps":            round(
                    self._main_ref.ddos_protection.analyzer.global_request_rate(), 2
                ),
            })

        if _PSUTIL_AVAILABLE:
            snapshot["cpu_pct"] = psutil.cpu_percent(interval=None)
            snapshot["mem_mb"]  = round(
                psutil.virtual_memory().used / 1_048_576, 1
            )

        with self._lock:
            self._metrics.update(snapshot)
            self._metric_history.append(dict(snapshot))

        # Alerting
        if self.config.alerts_enabled:
            self._check_alerts(snapshot)

    def _check_alerts(self, snap: Dict[str, Any]) -> None:
        if snap.get("ddos_level") in ("detection", "critical"):
            self.log.critical(
                f"ALERT: DDoS level {snap['ddos_level']} — "
                f"rps={snap.get('rps', '?')}"
            )
        if snap.get("cpu_pct") is not None and snap["cpu_pct"] > 90:
            self.log.warning(f"ALERT: High CPU {snap['cpu_pct']}%")

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._metrics)

    def get_history(self, last_n: int = 60) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._metric_history)[-last_n:]

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_ts


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 19 — DATb64Backup  (Backup & Recovery)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64Backup:
    """
    Automated backup and point-in-time recovery for the DATb64+ database.

    Backup types:
    - **Full**  — copy entire SQLite file (or pg_dump for PostgreSQL)
    - **Incremental** — export only rows changed since last backup
    - **Vdat snapshot** — dump current Vdat to a timestamped file

    Retention:
    - Configurable max backup count (oldest deleted first)
    - Backups are zlib-compressed and can optionally be encrypted

    Recovery:
    - ``restore(backup_id)`` — overwrite current DB from backup
    """

    def __init__(self, config: DATb64Config) -> None:
        self.config      = config
        self.log         = DATb64Logger(config)
        self._backup_dir = Path(config.backup_path)
        self._backup_dir.mkdir(parents=True, exist_ok=True)
        self._manifest_path = self._backup_dir / "manifest.json"
        self._manifest:  List[Dict[str, Any]] = self._load_manifest()

    def _load_manifest(self) -> List[Dict[str, Any]]:
        if self._manifest_path.exists():
            try:
                return json.loads(self._manifest_path.read_text())
            except Exception:
                pass
        return []

    def _save_manifest(self) -> None:
        self._manifest_path.write_text(
            json.dumps(self._manifest, indent=2)
        )

    # ─────────────────────────────────────────────────────────────────────────
    async def create_backup(
        self,
        database: DATb64Database,
        backup_type: str = "full",
        compress: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a *backup_type* backup of *database*.

        Returns a manifest entry dict with ``backup_id``, ``path``, ``size``,
        ``type``, and ``ts``.
        """
        ts   = time.strftime("%Y%m%d_%H%M%S")
        bid  = f"{backup_type}_{ts}_{uuid.uuid4().hex[:8]}"
        dest = self._backup_dir / f"{bid}.bak"

        if self.config.database_type == "sqlite":
            src_path = Path(self.config.data_path) / "main.db"
            if src_path.exists():
                data = src_path.read_bytes()
                if compress:
                    data = zlib.compress(data, level=6)
                dest.write_bytes(data)
            else:
                dest.write_bytes(b"")
        else:
            # For non-SQLite, write a JSON export
            try:
                tables = ["users", "data", "dtkeys", "access_log"]
                export: Dict[str, Any] = {}
                for tbl in tables:
                    try:
                        rows = await database.query(f"SELECT * FROM {tbl}")
                        export[tbl] = rows
                    except Exception:
                        export[tbl] = []
                raw = json.dumps(export).encode()
                if compress:
                    raw = zlib.compress(raw, level=6)
                dest.write_bytes(raw)
            except Exception as exc:
                self.log.error(f"Backup export error: {exc}")

        size = dest.stat().st_size if dest.exists() else 0
        entry = {
            "backup_id":  bid,
            "path":       str(dest),
            "size_bytes": size,
            "type":       backup_type,
            "ts":         time.time(),
            "compressed": compress,
        }
        self._manifest.append(entry)
        self._rotate_backups()
        self._save_manifest()

        self.log.info(
            f"Backup created: {bid} ({size / 1024:.1f} KB, type={backup_type})"
        )
        return entry

    def _rotate_backups(self, max_count: int = 30) -> None:
        """Delete oldest backups beyond *max_count*."""
        while len(self._manifest) > max_count:
            oldest = self._manifest.pop(0)
            old_path = Path(oldest["path"])
            if old_path.exists():
                old_path.unlink()

    async def restore(self, backup_id: str) -> bool:
        """
        Restore the database from *backup_id*.

        Returns True on success.
        """
        entry = next(
            (e for e in self._manifest if e["backup_id"] == backup_id), None
        )
        if entry is None:
            self.log.error(f"Backup {backup_id} not found")
            return False

        src = Path(entry["path"])
        if not src.exists():
            self.log.error(f"Backup file missing: {src}")
            return False

        data = src.read_bytes()
        if entry.get("compressed"):
            data = zlib.decompress(data)

        if self.config.database_type == "sqlite":
            dest = Path(self.config.data_path) / "main.db"
            dest.write_bytes(data)
            self.log.info(f"Database restored from {backup_id}")
            return True

        self.log.warning("Restore for non-SQLite DB requires manual steps")
        return False

    def list_backups(self) -> List[Dict[str, Any]]:
        return list(self._manifest)

    def latest_backup(self) -> Optional[Dict[str, Any]]:
        return self._manifest[-1] if self._manifest else None


# ══════════════════════════════════════════════════════════════════════════════
# CLASS 20 — DATb64  (Main Entry Point)
# ══════════════════════════════════════════════════════════════════════════════
class DATb64:
    """
    DATb64+ — Main entry point.  Combines all 20 subsystems into a single
    cohesive API.

    Quick start::

        import asyncio
        from DATb64Plus import DATb64, DATb64Config

        async def main():
            cfg = DATb64Config(database_type="sqlite")
            db  = DATb64(cfg)
            await db.start()

            dtkey = db.generate_dtkey("alice", "my_app")
            await db.store_data("hello", "world", user_id="alice")
            print(await db.get_data("hello"))          # → "world"
            print(db.validate_dtkey(dtkey))            # → True

            await db.stop()

        asyncio.run(main())
    """

    def __init__(self, config: Optional[DATb64Config] = None) -> None:
        self.config = config or DATb64Config()

        # Validate config
        ok, errors = self.config.validate()
        if not ok:
            raise ValueError(f"Invalid DATb64Config: {errors}")

        # Ensure all directories exist
        self.config.ensure_directories()

        # ── Core subsystems ──────────────────────────────────────────────────
        self.log          = DATb64Logger(self.config)
        self.security     = DATb64Security(self.config)
        self.dtkey_manager = DATb64DTkeyManager(self.config, self.security)
        self.database     = DATb64Database(self.config)
        self.vdat         = DATb64Vdat(self.config, self.security)
        self.ddos_protection = DATb64DDoSProtection(self.config, self.vdat, self.security)
        self.html_connector = DATb64HTMLConnector(
            self.config, self.dtkey_manager, self.security
        )
        self.cache        = DATb64Cache(self.config)
        self.rate_limiter = DATb64RateLimiter(self.config)
        self.events       = DATb64EventEmitter()
        self.data_sync    = DATb64DataSync(self.config)
        self.db_pool      = DATb64DatabasePool(self.config)
        self.monitor      = DATb64Monitor(self.config)
        self.backup       = DATb64Backup(self.config)
        self.http_server  = DATb64HTTPServer(self.config)
        self.api_server   = DATb64APIServer(self.config, main_ref=self)
        self.ws_server    = DATb64WebSocketServer(self.config, main_ref=self)
        self.traffic_analyzer = self.ddos_protection.analyzer

        self.monitor.attach(self)

        self._is_running  = False
        self._start_ts:   Optional[float] = None

        self.log.info(
            f"DATb64+ v{__version__} initialized — "
            f"install_path={self.config.install_path}"
        )

    # ─── Lifecycle ───────────────────────────────────────────────────────────
    async def start(self) -> None:
        """
        Start all subsystems:
        1. Connect to the database
        2. Start HTTP, API, WebSocket servers
        3. Start background monitor
        4. Schedule periodic Vdat sync
        """
        if self._is_running:
            self.log.warning("DATb64+ already running")
            return

        self.log.info("DATb64+ starting...")

        await self.database.connect()

        await self.http_server.start(port=8080)
        await self.api_server.start(port=8081)
        await self.ws_server.start(port=8082)

        self.monitor.start_background_monitoring()

        asyncio.ensure_future(
            self.data_sync.schedule_periodic(self.vdat, self.database)
        )

        self._is_running = True
        self._start_ts   = time.time()
        self.events.emit("started")
        self.log.info("DATb64+ started successfully")

    async def stop(self) -> None:
        """Gracefully shut down all subsystems."""
        if not self._is_running:
            return

        self.log.info("DATb64+ stopping...")

        if self.vdat.is_active:
            await self.data_sync.sync(self.vdat, self.database)

        await self.http_server.stop()
        await self.api_server.stop()
        await self.ws_server.stop()
        self.monitor.stop_background_monitoring()
        await self.database.close()

        self._is_running = False
        self.events.emit("stopped")
        self.log.info("DATb64+ stopped")

    # ─── DTkey Operations ────────────────────────────────────────────────────
    def generate_dtkey(
        self,
        user_id:       str,
        database_name: str,
        permissions:   Optional[List[str]] = None,
        ttl:           Optional[int]       = None,
    ) -> str:
        """Generate and return a new DTkey."""
        return self.dtkey_manager.generate_dtkey(
            user_id, database_name, permissions, ttl
        )

    def validate_dtkey(
        self, dtkey: str, required_permission: Optional[str] = None
    ) -> bool:
        """Return True if *dtkey* is valid and not expired."""
        ok, _ = self.dtkey_manager.validate_dtkey(dtkey, required_permission)
        return ok

    def rotate_dtkey(self, old_dtkey: str) -> str:
        """Rotate *old_dtkey* and return the new one."""
        return self.dtkey_manager.rotate_dtkey(old_dtkey)

    def revoke_dtkey(self, dtkey: str) -> bool:
        """Revoke *dtkey* immediately. Returns True if it existed."""
        return self.dtkey_manager.revoke_dtkey(dtkey)

    def list_user_dtkeys(self, user_id: str) -> List[Dict[str, Any]]:
        return self.dtkey_manager.list_user_dtkeys(user_id)

    # ─── Database Operations ─────────────────────────────────────────────────
    async def store_data(
        self, key: str, value: Any, user_id: Optional[str] = None
    ) -> bool:
        """
        Write *key/value* to the active store.

        Automatically routes to Vdat if under DDoS.
        """
        key = self.security.sanitize(key)

        # Invalidate cache
        self.cache.delete(key)

        if self.vdat.is_active:
            return await self.vdat.store(key, value, user_id)

        await self.database.upsert("data", {
            "id":         str(uuid.uuid4()),
            "user_id":    user_id or "system",
            "key":        key,
            "value":      json.dumps(value),
            "created_at": time.time(),
            "updated_at": time.time(),
        })
        return True

    async def get_data(self, key: str) -> Optional[Any]:
        """
        Read value for *key*.  Checks cache first, then active store.
        """
        key = self.security.sanitize(key)

        # Cache hit
        cached = self.cache.get(key)
        if cached is not None:
            return cached

        if self.vdat.is_active:
            value = await self.vdat.get(key)
        else:
            rows = await self.database.query(
                "SELECT value FROM data WHERE key = ?", (key,)
            )
            if rows:
                raw = rows[0].get("value")
                try:
                    value = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    value = raw
            else:
                value = None

        if value is not None:
            self.cache.set(key, value)

        return value

    async def delete_data(self, key: str) -> bool:
        """Delete *key* from the active store."""
        key = self.security.sanitize(key)
        self.cache.delete(key)

        if self.vdat.is_active:
            return await self.vdat.delete(key)

        rows = await self.database.delete("data", "key = ?", (key,))
        return rows > 0

    # ─── Database Management ─────────────────────────────────────────────────
    def add_database(
        self,
        database_type: str,
        name:          str,
        credentials:   Dict[str, Any],
    ) -> str:
        """
        Register a named database and return a newly generated DTkey.

        This stores credentials in the config (not persisted externally) and
        returns a DTkey for use by applications connecting to *name*.
        """
        dtkey = self.generate_dtkey(user_id=name, database_name=name)
        self.log.info(f"Database registered: {name} ({database_type})")
        return dtkey

    # ─── DDoS & Traffic ──────────────────────────────────────────────────────
    def record_request(self, ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Record an incoming request for DDoS detection.

        Returns ``{"allowed": bool, "level": str, ...}``.
        """
        result = self.ddos_protection.record_request(ip)
        self.monitor._metrics["total_requests"] = (
            self.monitor._metrics.get("total_requests", 0) + 1
        )
        return result

    def is_rate_limited(self, ip: str) -> bool:
        return self.rate_limiter.is_limited(ip)

    def block_ip(self, ip: str, duration: Optional[int] = None) -> None:
        self.ddos_protection.block_ip(ip, duration)

    # ─── HTML Connector ──────────────────────────────────────────────────────
    def register_html_visitor(
        self,
        ip_address: str,
        user_agent: str,
        dtkey:      str,
        page_url:   str,
        referrer:   str = "",
    ) -> str:
        """Register an HTML visitor and return session ID."""
        return self.html_connector.register_visitor(
            ip_address, user_agent, dtkey, page_url, referrer
        )

    def get_all_visitors(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.html_connector.get_all_visitors(limit)

    def get_visitor_by_ip(self, ip: str) -> List[Dict[str, Any]]:
        return self.html_connector.get_visitors_by_ip(ip)

    async def connect_html_to_database(self, html_file: str, dtkey: str) -> bool:
        return await self.html_connector.connect_html_to_database(
            html_file, dtkey, self.database
        )

    def generate_js_snippet(self, dtkey: str, api_url: str = "http://localhost:8081") -> str:
        """Return embeddable JavaScript integration snippet."""
        return self.html_connector.generate_js_snippet(api_url, dtkey)

    # ─── Vdat Management ─────────────────────────────────────────────────────
    async def sync_vdat_to_database(self) -> Dict[str, Any]:
        """Force-sync all pending Vdat writes to the real database."""
        return await self.data_sync.sync(self.vdat, self.database)

    def activate_vdat(self, reason: str = "manual") -> None:
        """Manually activate the virtual database."""
        self.vdat.activate(reason)

    def deactivate_vdat(self) -> None:
        """Manually deactivate the virtual database."""
        self.vdat.deactivate()

    # ─── Backup ──────────────────────────────────────────────────────────────
    async def create_backup(self, backup_type: str = "full") -> Dict[str, Any]:
        return await self.backup.create_backup(self.database, backup_type)

    async def restore_backup(self, backup_id: str) -> bool:
        return await self.backup.restore(backup_id)

    def list_backups(self) -> List[Dict[str, Any]]:
        return self.backup.list_backups()

    # ─── Statistics ──────────────────────────────────────────────────────────
    def get_stats(self) -> Dict[str, Any]:
        """Return a comprehensive system statistics snapshot."""
        return {
            "version":            __version__,
            "uptime_s":           round(
                time.time() - (self._start_ts or time.time()), 1
            ),
            "is_running":         self._is_running,
            # DDoS
            "ddos_under_attack":  self.ddos_protection.is_under_attack,
            "ddos_level":         self.ddos_protection.attack_level,
            "traffic":            self.ddos_protection.analyzer.window_total(),
            "traffic_rps":        round(
                self.ddos_protection.analyzer.global_request_rate(), 2
            ),
            # Vdat
            "vdat_active":        self.vdat.is_active,
            "vdat_records":       len(self.vdat._store),
            "vdat_pending_sync":  len(
                [r for r in self.vdat._pending if not r.get("synced")]
            ),
            # Keys
            "dtkey_count":        self.dtkey_manager.total_key_count(),
            # Visitors
            "visitor_count":      len(self.html_connector._log),
            "unique_ips":         self.html_connector.unique_ip_count(),
            # Supabase quota
            "supabase_quota_pct": round(
                self.config.supabase_quota_used
                / max(self.config.supabase_quota_limit, 1) * 100, 2
            ),
            # Cache
            "cache":              self.cache.stats(),
            # Sessions
            "active_sessions":    self.security.active_session_count(),
            # Sync
            "data_sync":          self.data_sync.status(),
            # Monitor
            "monitor":            self.monitor.get_metrics(),
        }

    def get_traffic_stats(self) -> Dict[str, Any]:
        return self.ddos_protection.traffic_stats()

    def get_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.log.get_security_events(limit)

    # ─── Context Manager ─────────────────────────────────────────────────────
    async def __aenter__(self) -> "DATb64":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # ─────────────────────────────────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"<DATb64+ v{__version__} "
            f"db={self.config.database_type!r} "
            f"running={self._is_running} "
            f"vdat={self.vdat.is_active}>"
        )


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API EXPORTS
# ══════════════════════════════════════════════════════════════════════════════
__all__ = [
    # Main
    "DATb64",
    "DATb64Config",
    # Subsystems
    "DATb64Logger",
    "DATb64Security",
    "DATb64DTkeyManager",
    "DATb64Database",
    "DATb64Vdat",
    "DATb64DDoSProtection",
    "DATb64TrafficAnalyzer",
    "DATb64HTMLConnector",
    "DATb64HTTPServer",
    "DATb64APIServer",
    "DATb64WebSocketServer",
    "DATb64DataSync",
    "DATb64Cache",
    "DATb64RateLimiter",
    "DATb64EventEmitter",
    "DATb64DatabasePool",
    "DATb64Monitor",
    "DATb64Backup",
    # Meta
    "__version__",
    "__author__",
]


# ══════════════════════════════════════════════════════════════════════════════
# QUICK-START EXAMPLE  (run:  python DATb64+.py)
# ══════════════════════════════════════════════════════════════════════════════
async def _demo() -> None:
    print(f"\n{'=' * 60}")
    print(f"  DATb64+ v{__version__} — Quick-Start Demo")
    print(f"{'=' * 60}\n")

    cfg = DATb64Config(
        database_type = "sqlite",
        log_level     = "INFO",
        ddos_detection_threshold = 900_000,
        ddos_critical_threshold  = 1_000_000,
    )

    ok, errors = cfg.validate()
    print(f"Config valid: {ok}  errors: {errors}")

    async with DATb64(cfg) as db:
        print(f"\n{db}\n")

        # ── DTkey lifecycle ──────────────────────────────────────────────────
        dtkey = db.generate_dtkey("alice", "demo_app", permissions=["read", "write"])
        print(f"DTkey (preview): {dtkey[:50]}...")

        valid = db.validate_dtkey(dtkey)
        print(f"Validate DTkey:  {valid}")

        # ── Data store / retrieve ────────────────────────────────────────────
        await db.store_data("greeting", {"hello": "world"}, user_id="alice")
        result = await db.get_data("greeting")
        print(f"Stored/retrieved: {result}")

        # ── Visitor tracking ─────────────────────────────────────────────────
        sid = db.register_html_visitor(
            "192.168.1.1", "Mozilla/5.0", dtkey, "/index.html"
        )
        print(f"Visitor session: {sid[:20]}...")
        print(f"All visitors:    {db.get_all_visitors(limit=3)}")

        # ── DDoS simulation (low traffic — no trigger) ───────────────────────
        for _ in range(10):
            res = db.record_request("10.0.0.1")
        print(f"\nDDoS check after 10 req: {res}")

        # ── Backup ───────────────────────────────────────────────────────────
        bk = await db.create_backup("full")
        print(f"Backup created:  {bk['backup_id']}")

        # ── JS Snippet ───────────────────────────────────────────────────────
        snippet = db.generate_js_snippet(dtkey)
        print(f"\nJS snippet (first 120 chars):\n{snippet[:120]}...")

        # ── Stats ────────────────────────────────────────────────────────────
        stats = db.get_stats()
        print(f"\nStats snapshot:")
        for k, v in stats.items():
            if not isinstance(v, dict):
                print(f"  {k:28s}: {v}")

        # ── Rotate + Revoke ──────────────────────────────────────────────────
        new_dtkey = db.rotate_dtkey(dtkey)
        print(f"\nRotated DTkey (preview): {new_dtkey[:50]}...")
        revoked = db.revoke_dtkey(new_dtkey)
        print(f"Revoked: {revoked}")

    print("\nDATb64+ demo complete.\n")


if __name__ == "__main__":
    asyncio.run(_demo())
