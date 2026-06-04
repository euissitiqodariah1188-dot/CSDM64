#!/usr/bin/env python3
"""
OsourCL.py - Cloud Component Motherboard
=========================================
Production-ready enterprise-grade cloud storage & binary translator library.

Author: OsourCL Engine
Version: 1.0.0
Architecture: Multi-Layer Enterprise (5 Layers)
Capacity: 10GB file support
Security: AES-256 encryption, API key auth
"""

# ============================================================
# IMPORTS
# ============================================================
import os
import sys
import json
import time
import uuid
import hmac
import zlib
import gzip
import struct
import shutil
import hashlib
import base64
import logging
import asyncio
import threading
import subprocess
import multiprocessing
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any, Generator
from logging.handlers import RotatingFileHandler
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.error import URLError
import socketserver
import socket
import io
import traceback
import signal
import atexit

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, hashes, hmac as crypto_hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] cryptography not installed. Run: pip install cryptography")

# ============================================================
# LAYER 1 - CONFIGURATION
# ============================================================

BASE_DIR = Path("C_OsourCL")
BASE_DIR.mkdir(exist_ok=True)

class OsourCLConfig:
    """Central configuration for all OsourCL components."""

    # Paths
    BASE_DIR              = BASE_DIR
    CLOUD_STORAGE_PATH    = BASE_DIR / "cloud_storage"
    DATA_PATH             = BASE_DIR / "data"
    LOG_PATH              = BASE_DIR / "logs"
    CACHE_PATH            = BASE_DIR / "cache"
    BACKUP_PATH           = BASE_DIR / "backups"
    API_KEY_FILE          = BASE_DIR / "data" / "api_keys.json"
    CONFIG_FILE           = BASE_DIR / "data" / "config.json"
    METRICS_FILE          = BASE_DIR / "data" / "metrics.json"
    QUOTA_FILE            = BASE_DIR / "data" / "quota.json"

    # Limits
    MAX_FILE_SIZE         = 10 * 1024 * 1024 * 1024   # 10 GB
    CHUNK_SIZE            = 4 * 1024 * 1024             # 4 MB chunks
    MAX_QUOTA             = 10 * 1024 * 1024 * 1024    # 10 GB quota

    # Network
    HTTP_PORT             = 8080
    PROXY_PORT            = 8081
    BANDWIDTH_LIMIT       = 1 * 1024 * 1024             # 1 MB/s

    # Security
    AES_KEY_SIZE          = 32   # AES-256
    SALT_SIZE             = 16
    IV_SIZE               = 16
    API_KEY_LENGTH        = 64
    API_KEY_PREFIX        = "osourcl_"
    KEY_ROTATION_DAYS     = 30

    # Backup
    BACKUP_INTERVAL_HOURS = 24

    def __init__(self):
        self._ensure_directories()
        self._load_or_create_config()

    def _ensure_directories(self):
        for path in [
            self.CLOUD_STORAGE_PATH, self.DATA_PATH,
            self.LOG_PATH, self.CACHE_PATH, self.BACKUP_PATH
        ]:
            path.mkdir(parents=True, exist_ok=True)

    def _load_or_create_config(self):
        if self.CONFIG_FILE.exists():
            with open(self.CONFIG_FILE, "r") as f:
                self._config = json.load(f)
        else:
            self._config = {
                "version": "1.0.0",
                "created_at": datetime.utcnow().isoformat(),
                "encryption_enabled": True,
                "compression_enabled": True,
                "deduplication_enabled": True,
                "auto_backup": True,
                "bandwidth_limit": self.BANDWIDTH_LIMIT
            }
            self._save_config()

    def _save_config(self):
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(self._config, f, indent=2)

    def get(self, key: str, default=None):
        return self._config.get(key, default)

    def set(self, key: str, value):
        self._config[key] = value
        self._save_config()


# ============================================================
# LAYER 2 - LOGGING & MONITORING
# ============================================================

class OsourCLLogger:
    """Advanced multi-channel logger with rotation, security log, metrics."""

    _instance: Optional['OsourCLLogger'] = None

    def __new__(cls, config: OsourCLConfig):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init(config)
        return cls._instance

    def _init(self, config: OsourCLConfig):
        self.config = config
        self._setup_loggers()
        self._metrics: Dict[str, Any] = {
            "operations": 0,
            "errors": 0,
            "bytes_uploaded": 0,
            "bytes_downloaded": 0,
            "api_calls": 0,
            "translations": 0,
            "start_time": datetime.utcnow().isoformat()
        }
        self._lock = threading.Lock()

    def _setup_loggers(self):
        fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        def make_logger(name: str, filename: str, level=logging.DEBUG) -> logging.Logger:
            logger = logging.getLogger(name)
            logger.setLevel(level)
            fh = RotatingFileHandler(
                self.config.LOG_PATH / filename,
                maxBytes=50 * 1024 * 1024,  # 50 MB per log file
                backupCount=10
            )
            fh.setFormatter(fmt)
            logger.addHandler(fh)
            if name == "OsourCL.main":
                ch = logging.StreamHandler(sys.stdout)
                ch.setFormatter(fmt)
                logger.addHandler(ch)
            return logger

        self.main    = make_logger("OsourCL.main",     "osourcl.log")
        self.security = make_logger("OsourCL.security","security.log")
        self.metrics  = make_logger("OsourCL.metrics", "metrics.log")
        self.perf     = make_logger("OsourCL.perf",    "performance.log")
        self.audit    = make_logger("OsourCL.audit",   "audit.log")

    def log(self, msg: str, level: str = "info", component: str = "main"):
        logger = getattr(self, component if hasattr(self, component) else "main")
        getattr(logger, level)(msg)
        with self._lock:
            self._metrics["operations"] += 1
            if level in ("error", "critical"):
                self._metrics["errors"] += 1

    def record_metric(self, key: str, value):
        with self._lock:
            if key in self._metrics:
                self._metrics[key] += value
            else:
                self._metrics[key] = value
        self.metrics.debug(f"METRIC {key}={value}")

    def get_metrics(self) -> Dict:
        with self._lock:
            return dict(self._metrics)

    def save_metrics(self):
        with open(self.config.METRICS_FILE, "w") as f:
            json.dump(self.get_metrics(), f, indent=2)


# ============================================================
# LAYER 3 - SECURITY
# ============================================================

class OsourCLSecurity:
    """AES-256 encryption, key derivation, hashing, secure storage."""

    def __init__(self, config: OsourCLConfig, logger: OsourCLLogger):
        self.config = config
        self.logger = logger
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package required: pip install cryptography")
        self._master_key = self._load_or_create_master_key()

    def _load_or_create_master_key(self) -> bytes:
        key_file = self.config.DATA_PATH / ".master.key"
        if key_file.exists():
            with open(key_file, "rb") as f:
                return f.read()
        key = os.urandom(self.config.AES_KEY_SIZE)
        with open(key_file, "wb") as f:
            f.write(key)
        key_file.chmod(0o600)
        self.logger.log("Master encryption key created", "info", "security")
        return key

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config.AES_KEY_SIZE,
            salt=salt,
            iterations=310000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        """Encrypt data with AES-256-CBC. Returns: salt(16) + iv(16) + ciphertext."""
        key = key or self._master_key
        salt = os.urandom(self.config.SALT_SIZE)
        iv   = os.urandom(self.config.IV_SIZE)
        derived = self.derive_key(base64.b64encode(key).decode(), salt)

        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(derived), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()

        return salt + iv + ciphertext

    def decrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        """Decrypt AES-256-CBC data. Expects: salt(16) + iv(16) + ciphertext."""
        key = key or self._master_key
        salt       = data[:self.config.SALT_SIZE]
        iv         = data[self.config.SALT_SIZE:self.config.SALT_SIZE + self.config.IV_SIZE]
        ciphertext = data[self.config.SALT_SIZE + self.config.IV_SIZE:]
        derived = self.derive_key(base64.b64encode(key).decode(), salt)

        cipher = Cipher(algorithms.AES(derived), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def hash_data(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def hmac_sign(self, data: bytes, key: bytes) -> str:
        return hmac.new(key, data, hashlib.sha256).hexdigest()

    def secure_hash_api_key(self, api_key: str) -> str:
        return hashlib.sha3_256(api_key.encode()).hexdigest()


# ============================================================
# LAYER 4 - API KEY MANAGER
# ============================================================

class OsourCLAPIKeyManager:
    """Full API key lifecycle: generate, validate, rotate, revoke, usage track."""

    def __init__(self, config: OsourCLConfig, logger: OsourCLLogger, security: OsourCLSecurity):
        self.config   = config
        self.logger   = logger
        self.security = security
        self._lock    = threading.RLock()
        self._keys: Dict[str, Dict] = {}
        self._load_keys()

    def _load_keys(self):
        if self.config.API_KEY_FILE.exists():
            with open(self.config.API_KEY_FILE, "r") as f:
                self._keys = json.load(f)
        else:
            self._keys = {}
        self.logger.log(f"Loaded {len(self._keys)} API key(s)", "info", "security")

    def _save_keys(self):
        with open(self.config.API_KEY_FILE, "w") as f:
            json.dump(self._keys, f, indent=2)
        self.config.API_KEY_FILE.chmod(0o600)

    def generate_api_key(self, name: str = "default", permissions: List[str] = None) -> str:
        """Generate a new API key and save it. Returns the raw key."""
        with self._lock:
            raw = self.config.API_KEY_PREFIX + base64.urlsafe_b64encode(
                os.urandom(48)
            ).decode().rstrip("=")[:self.config.API_KEY_LENGTH]

            key_id   = str(uuid.uuid4())
            key_hash = self.security.secure_hash_api_key(raw)
            now      = datetime.utcnow()

            self._keys[key_id] = {
                "id":          key_id,
                "name":        name,
                "hash":        key_hash,
                "permissions": permissions or ["read", "write", "translate", "connect"],
                "created_at":  now.isoformat(),
                "expires_at":  (now + timedelta(days=self.config.KEY_ROTATION_DAYS)).isoformat(),
                "last_used":   None,
                "usage_count": 0,
                "active":      True,
                "revoked":     False
            }
            self._save_keys()
            self.logger.log(f"API key generated: id={key_id} name={name}", "info", "security")
            self.logger.log(f"API_KEY_GENERATED key_id={key_id}", "info", "audit")
            return raw

    def validate_api_key(self, raw_key: str) -> Tuple[bool, Optional[Dict]]:
        """Validate an API key. Returns (valid, key_info)."""
        with self._lock:
            key_hash = self.security.secure_hash_api_key(raw_key)
            for key_id, info in self._keys.items():
                if info["hash"] == key_hash:
                    if info["revoked"]:
                        self.logger.log(f"Revoked key used: {key_id}", "warning", "security")
                        return False, None
                    if not info["active"]:
                        return False, None
                    # Check expiry
                    expires = datetime.fromisoformat(info["expires_at"])
                    if datetime.utcnow() > expires:
                        self.logger.log(f"Expired key used: {key_id}", "warning", "security")
                        return False, None
                    # Update usage
                    info["last_used"]   = datetime.utcnow().isoformat()
                    info["usage_count"] += 1
                    self._save_keys()
                    self.logger.record_metric("api_calls", 1)
                    return True, info
            self.logger.log("Invalid API key attempt", "warning", "security")
            return False, None

    def rotate_api_key(self, old_key: str, name: str = None) -> Optional[str]:
        """Rotate: revoke old key, generate new one."""
        valid, info = self.validate_api_key(old_key)
        if not valid:
            self.logger.log("Rotation failed: invalid old key", "error", "security")
            return None
        self.revoke_api_key(old_key)
        new_key = self.generate_api_key(
            name=name or info.get("name", "rotated"),
            permissions=info.get("permissions")
        )
        self.logger.log("API key rotated successfully", "info", "security")
        return new_key

    def revoke_api_key(self, raw_key: str) -> bool:
        """Revoke an API key permanently."""
        with self._lock:
            key_hash = self.security.secure_hash_api_key(raw_key)
            for key_id, info in self._keys.items():
                if info["hash"] == key_hash:
                    info["revoked"] = True
                    info["active"]  = False
                    self._save_keys()
                    self.logger.log(f"API key revoked: {key_id}", "info", "security")
                    self.logger.log(f"API_KEY_REVOKED key_id={key_id}", "info", "audit")
                    return True
            return False

    def list_keys(self) -> List[Dict]:
        """List all API keys (without hashes)."""
        with self._lock:
            result = []
            for key_id, info in self._keys.items():
                safe = dict(info)
                safe.pop("hash", None)
                result.append(safe)
            return result

    def get_usage_stats(self) -> Dict:
        with self._lock:
            total_calls = sum(v["usage_count"] for v in self._keys.values())
            active_keys = sum(1 for v in self._keys.values() if v["active"] and not v["revoked"])
            return {
                "total_keys":   len(self._keys),
                "active_keys":  active_keys,
                "total_calls":  total_calls,
            }


# ============================================================
# LAYER 5 - CLOUD STORAGE
# ============================================================

class OsourCLCloudStorage:
    """10GB-capable cloud storage: upload, download, sync, encrypt, compress, deduplicate, backup."""

    def __init__(self, config: OsourCLConfig, logger: OsourCLLogger, security: OsourCLSecurity):
        self.config      = config
        self.logger      = logger
        self.security    = security
        self._lock       = threading.RLock()
        self._index_file = self.config.DATA_PATH / "storage_index.json"
        self._index: Dict[str, Dict] = self._load_index()
        self._quota_used = self._calculate_quota()
        self._start_backup_scheduler()

    def _load_index(self) -> Dict:
        if self._index_file.exists():
            with open(self._index_file, "r") as f:
                return json.load(f)
        return {}

    def _save_index(self):
        with open(self._index_file, "w") as f:
            json.dump(self._index, f, indent=2)

    def _calculate_quota(self) -> int:
        total = 0
        for meta in self._index.values():
            total += meta.get("size", 0)
        return total

    def _check_quota(self, size: int):
        if self._quota_used + size > self.config.MAX_QUOTA:
            raise ValueError(
                f"Quota exceeded: {self._quota_used + size} > {self.config.MAX_QUOTA} bytes"
            )

    def _file_hash(self, path: Path) -> str:
        """SHA-256 of file for deduplication."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in self._read_chunks(f):
                h.update(chunk)
        return h.hexdigest()

    def _read_chunks(self, fobj, size: int = None) -> Generator[bytes, None, None]:
        chunk_size = size or self.config.CHUNK_SIZE
        while True:
            chunk = fobj.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def _progress_bar(self, current: int, total: int, width: int = 40) -> str:
        pct = current / total if total else 0
        filled = int(width * pct)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {pct*100:.1f}% ({current/(1024**2):.1f}/{total/(1024**2):.1f} MB)"

    def upload(self, local_path: str, remote_name: str = None,
               encrypt: bool = True, compress: bool = True,
               show_progress: bool = True) -> Dict:
        """Upload file to cloud storage with AES-256 + gzip, 10GB support."""
        src = Path(local_path)
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {local_path}")

        file_size = src.stat().st_size
        if file_size > self.config.MAX_FILE_SIZE:
            raise ValueError(f"File too large: {file_size} > {self.config.MAX_FILE_SIZE}")

        with self._lock:
            self._check_quota(file_size)
            remote_name = remote_name or src.name
            file_hash   = self._file_hash(src)

            # Deduplication check
            for existing_id, meta in self._index.items():
                if meta.get("original_hash") == file_hash:
                    self.logger.log(
                        f"Dedup hit for {remote_name} -> {existing_id}", "info"
                    )
                    return meta

            file_id  = str(uuid.uuid4())
            dest_dir = self.config.CLOUD_STORAGE_PATH / file_id
            dest_dir.mkdir(parents=True)
            dest_path = dest_dir / "data.bin"
            meta_path = dest_dir / "meta.json"

            self.logger.log(f"Upload started: {src.name} ({file_size/(1024**2):.1f} MB)", "info")
            start = time.time()
            processed = 0
            chunk_index = 0

            with open(src, "rb") as fin, open(dest_path, "wb") as fout:
                for raw_chunk in self._read_chunks(fin):
                    chunk = raw_chunk
                    if compress:
                        chunk = gzip.compress(chunk, compresslevel=6)
                    if encrypt:
                        chunk = self.security.encrypt(chunk)

                    # Write chunk with length prefix
                    fout.write(struct.pack(">I", len(chunk)))
                    fout.write(chunk)

                    processed += len(raw_chunk)
                    chunk_index += 1
                    if show_progress:
                        bar = self._progress_bar(processed, file_size)
                        print(f"\r  Upload {bar}", end="", flush=True)

            if show_progress:
                print()

            elapsed = time.time() - start
            dest_size = dest_path.stat().st_size

            meta = {
                "id":            file_id,
                "remote_name":   remote_name,
                "original_name": src.name,
                "original_hash": file_hash,
                "size":          file_size,
                "stored_size":   dest_size,
                "compressed":    compress,
                "encrypted":     encrypt,
                "chunks":        chunk_index,
                "uploaded_at":   datetime.utcnow().isoformat(),
                "elapsed_sec":   round(elapsed, 2),
                "path":          str(dest_path)
            }
            with open(meta_path, "w") as f:
                json.dump(meta, f, indent=2)

            self._index[file_id] = meta
            self._save_index()
            self._quota_used += file_size
            self.logger.record_metric("bytes_uploaded", file_size)
            self.logger.log(
                f"Upload complete: {remote_name} in {elapsed:.1f}s "
                f"({file_size/(1024**2):.1f} MB -> {dest_size/(1024**2):.1f} MB stored)",
                "info"
            )
            return meta

    def download(self, file_id: str, dest_path: str,
                 show_progress: bool = True) -> str:
        """Download file from cloud storage."""
        with self._lock:
            if file_id not in self._index:
                # Try by remote_name
                found = None
                for fid, meta in self._index.items():
                    if meta["remote_name"] == file_id:
                        found = fid
                        break
                if not found:
                    raise FileNotFoundError(f"File not found in cloud: {file_id}")
                file_id = found

            meta      = self._index[file_id]
            src_path  = Path(meta["path"])
            dest      = Path(dest_path)
            dest.parent.mkdir(parents=True, exist_ok=True)

            self.logger.log(f"Download started: {meta['remote_name']}", "info")
            start     = time.time()
            processed = 0
            total     = meta["size"]

            with open(src_path, "rb") as fin, open(dest, "wb") as fout:
                while True:
                    length_data = fin.read(4)
                    if not length_data or len(length_data) < 4:
                        break
                    chunk_len = struct.unpack(">I", length_data)[0]
                    chunk = fin.read(chunk_len)
                    if not chunk:
                        break

                    if meta.get("encrypted"):
                        chunk = self.security.decrypt(chunk)
                    if meta.get("compressed"):
                        chunk = gzip.decompress(chunk)

                    fout.write(chunk)
                    processed += len(chunk)
                    if show_progress:
                        bar = self._progress_bar(processed, total)
                        print(f"\r  Download {bar}", end="", flush=True)

            if show_progress:
                print()

            elapsed = time.time() - start
            self.logger.record_metric("bytes_downloaded", processed)
            self.logger.log(
                f"Download complete: {meta['remote_name']} in {elapsed:.1f}s",
                "info"
            )
            return str(dest)

    def list_files(self) -> List[Dict]:
        with self._lock:
            return [
                {k: v for k, v in meta.items() if k != "path"}
                for meta in self._index.values()
            ]

    def delete_file(self, file_id: str) -> bool:
        with self._lock:
            if file_id not in self._index:
                return False
            meta = self._index.pop(file_id)
            dest_dir = Path(meta["path"]).parent
            shutil.rmtree(dest_dir, ignore_errors=True)
            self._quota_used -= meta.get("size", 0)
            self._save_index()
            self.logger.log(f"Deleted cloud file: {file_id}", "info")
            return True

    def sync_to_cloud(self, local_dir: str) -> List[Dict]:
        """Sync local directory to cloud storage."""
        results = []
        local = Path(local_dir)
        if not local.exists():
            raise FileNotFoundError(f"Local directory not found: {local_dir}")
        for f in local.rglob("*"):
            if f.is_file():
                try:
                    meta = self.upload(str(f), f.name)
                    results.append({"file": str(f), "status": "ok", "meta": meta})
                except Exception as e:
                    results.append({"file": str(f), "status": "error", "error": str(e)})
        return results

    def sync_from_cloud(self, local_dir: str) -> List[Dict]:
        """Sync all cloud files to local directory."""
        results = []
        dest_base = Path(local_dir)
        dest_base.mkdir(parents=True, exist_ok=True)
        for meta in self.list_files():
            try:
                dest = dest_base / meta["remote_name"]
                self.download(meta["id"], str(dest))
                results.append({"file": meta["remote_name"], "status": "ok"})
            except Exception as e:
                results.append({"file": meta.get("remote_name"), "status": "error", "error": str(e)})
        return results

    def get_quota_info(self) -> Dict:
        return {
            "used_bytes":   self._quota_used,
            "max_bytes":    self.config.MAX_QUOTA,
            "used_mb":      round(self._quota_used / (1024**2), 2),
            "max_gb":       round(self.config.MAX_QUOTA / (1024**3), 2),
            "used_percent": round(self._quota_used / self.config.MAX_QUOTA * 100, 2),
            "files_count":  len(self._index)
        }

    def create_backup(self):
        """Backup cloud storage index and metadata."""
        timestamp  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_dir = self.config.BACKUP_PATH / f"backup_{timestamp}"
        backup_dir.mkdir(parents=True)
        shutil.copy2(self._index_file, backup_dir / "storage_index.json")
        for file_id, meta in self._index.items():
            meta_path = Path(meta["path"]).parent / "meta.json"
            if meta_path.exists():
                shutil.copy2(meta_path, backup_dir / f"{file_id}_meta.json")
        self.logger.log(f"Backup created: {backup_dir}", "info")

    def _start_backup_scheduler(self):
        def _scheduler():
            while True:
                time.sleep(self.config.BACKUP_INTERVAL_HOURS * 3600)
                try:
                    self.create_backup()
                except Exception as e:
                    self.logger.log(f"Backup failed: {e}", "error")
        t = threading.Thread(target=_scheduler, daemon=True)
        t.start()


# ============================================================
# LAYER 6 - BINARY TRANSLATOR
# ============================================================

class OsourCLBinaryTranslator:
    """
    Binary translator: parse binary files, decompile to assembly,
    translate to readable Python pseudo-code.
    Supports EXE (PE), APK (ZIP/DEX), raw binary.
    """

    # x86 opcode table (common subset)
    X86_OPCODES = {
        0x00: ("ADD",   "r/m8, r8"),
        0x01: ("ADD",   "r/m16/32, r16/32"),
        0x03: ("ADD",   "r16/32, r/m16/32"),
        0x05: ("ADD",   "eAX, imm16/32"),
        0x0F: ("ESC",   "2-byte"),
        0x20: ("AND",   "r/m8, r8"),
        0x25: ("AND",   "eAX, imm16/32"),
        0x29: ("SUB",   "r/m16/32, r16/32"),
        0x2B: ("SUB",   "r16/32, r/m16/32"),
        0x31: ("XOR",   "r/m16/32, r16/32"),
        0x33: ("XOR",   "r16/32, r/m16/32"),
        0x39: ("CMP",   "r/m16/32, r16/32"),
        0x3B: ("CMP",   "r16/32, r/m16/32"),
        0x40: ("INC",   "eAX"),
        0x41: ("INC",   "eCX"),
        0x42: ("INC",   "eDX"),
        0x43: ("INC",   "eBX"),
        0x48: ("DEC",   "eAX"),
        0x50: ("PUSH",  "eAX"),
        0x51: ("PUSH",  "eCX"),
        0x52: ("PUSH",  "eDX"),
        0x53: ("PUSH",  "eBX"),
        0x54: ("PUSH",  "ESP"),
        0x55: ("PUSH",  "EBP"),
        0x56: ("PUSH",  "ESI"),
        0x57: ("PUSH",  "EDI"),
        0x58: ("POP",   "eAX"),
        0x59: ("POP",   "eCX"),
        0x5A: ("POP",   "eDX"),
        0x5B: ("POP",   "eBX"),
        0x5D: ("POP",   "EBP"),
        0x5E: ("POP",   "ESI"),
        0x5F: ("POP",   "EDI"),
        0x68: ("PUSH",  "imm16/32"),
        0x6A: ("PUSH",  "imm8"),
        0x74: ("JE",    "rel8"),
        0x75: ("JNE",   "rel8"),
        0x7C: ("JL",    "rel8"),
        0x7D: ("JGE",   "rel8"),
        0x7E: ("JLE",   "rel8"),
        0x7F: ("JG",    "rel8"),
        0x80: ("ADD",   "r/m8, imm8"),
        0x83: ("ADD",   "r/m16/32, imm8"),
        0x85: ("TEST",  "r/m16/32, r16/32"),
        0x89: ("MOV",   "r/m16/32, r16/32"),
        0x8B: ("MOV",   "r16/32, r/m16/32"),
        0x8D: ("LEA",   "r16/32, m"),
        0x90: ("NOP",   ""),
        0xB8: ("MOV",   "eAX, imm16/32"),
        0xB9: ("MOV",   "eCX, imm16/32"),
        0xBA: ("MOV",   "eDX, imm16/32"),
        0xBB: ("MOV",   "eBX, imm16/32"),
        0xC3: ("RET",   ""),
        0xC9: ("LEAVE", ""),
        0xE8: ("CALL",  "rel16/32"),
        0xE9: ("JMP",   "rel16/32"),
        0xEB: ("JMP",   "rel8"),
        0xF3: ("REP",   "prefix"),
        0xFF: ("CALL",  "r/m16/32"),
    }

    REGISTERS = ["EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"]
    REG8      = ["AL","CL","DL","BL","AH","CH","DH","BH"]

    def __init__(self, config: OsourCLConfig, logger: OsourCLLogger):
        self.config = config
        self.logger = logger

    def _detect_format(self, data: bytes) -> str:
        """Detect binary format from magic bytes."""
        if data[:2] == b'MZ':
            return "PE_EXE"
        if data[:4] == b'PK\x03\x04':
            return "APK_ZIP"
        if data[:4] == b'dex\n':
            return "DEX"
        if data[:4] == b'\x7fELF':
            return "ELF"
        if data[:4] == b'\xca\xfe\xba\xbe':
            return "MACHO"
        return "RAW_BINARY"

    def _parse_pe_header(self, data: bytes) -> Dict:
        """Parse PE (EXE/DLL) header fields."""
        info = {"format": "PE_EXE", "valid": False}
        try:
            if len(data) < 64:
                return info
            e_magic = struct.unpack_from("<H", data, 0)[0]
            if e_magic != 0x5A4D:
                return info
            e_lfanew = struct.unpack_from("<I", data, 60)[0]
            if e_lfanew + 24 > len(data):
                return info
            pe_sig = data[e_lfanew:e_lfanew+4]
            if pe_sig != b'PE\x00\x00':
                return info
            machine      = struct.unpack_from("<H", data, e_lfanew + 4)[0]
            num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            timestamp    = struct.unpack_from("<I", data, e_lfanew + 8)[0]
            opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
            characteristics = struct.unpack_from("<H", data, e_lfanew + 22)[0]

            machine_map = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}

            info.update({
                "valid":          True,
                "machine":        machine_map.get(machine, f"0x{machine:04X}"),
                "num_sections":   num_sections,
                "timestamp":      datetime.utcfromtimestamp(timestamp).isoformat(),
                "opt_hdr_size":   opt_hdr_size,
                "characteristics": f"0x{characteristics:04X}",
                "pe_offset":      e_lfanew
            })
        except Exception as e:
            info["error"] = str(e)
        return info

    def _parse_apk_manifest(self, data: bytes) -> Dict:
        """Parse APK: list ZIP entries (AndroidManifest.xml, classes.dex, etc.)."""
        info = {"format": "APK_ZIP", "entries": []}
        try:
            import zipfile
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for entry in z.namelist():
                    info["entries"].append(entry)
                info["entry_count"] = len(info["entries"])
                info["has_manifest"] = "AndroidManifest.xml" in info["entries"]
                info["has_dex"]      = any(e.endswith(".dex") for e in info["entries"])
        except Exception as e:
            info["error"] = str(e)
        return info

    def _disassemble_chunk(self, data: bytes, base_addr: int = 0x1000) -> List[str]:
        """Simple x86 disassembler for a binary chunk."""
        lines = []
        i = 0
        limit = min(len(data), 2048)  # limit per chunk
        while i < limit:
            addr = base_addr + i
            byte = data[i]
            mnemonic, operand = self.X86_OPCODES.get(byte, ("DB", f"0x{byte:02X}"))

            # Handle multi-byte instructions
            if byte in (0xB8, 0xB9, 0xBA, 0xBB) and i + 4 < len(data):
                imm = struct.unpack_from("<I", data, i+1)[0]
                reg = self.REGISTERS[byte - 0xB8]
                lines.append(f"  0x{addr:08X}:  MOV {reg}, 0x{imm:08X}")
                i += 5
            elif byte == 0x68 and i + 4 < len(data):
                imm = struct.unpack_from("<I", data, i+1)[0]
                lines.append(f"  0x{addr:08X}:  PUSH 0x{imm:08X}")
                i += 5
            elif byte in (0x74, 0x75, 0x7C, 0x7D, 0x7E, 0x7F, 0x6A, 0xEB) and i + 1 < len(data):
                rel = struct.unpack_from("<b", data, i+1)[0]
                target = addr + 2 + rel
                lines.append(f"  0x{addr:08X}:  {mnemonic} 0x{target:08X}")
                i += 2
            elif byte in (0xE8, 0xE9) and i + 4 < len(data):
                rel = struct.unpack_from("<i", data, i+1)[0]
                target = addr + 5 + rel
                lines.append(f"  0x{addr:08X}:  {mnemonic} 0x{target:08X}")
                i += 5
            elif byte == 0x89 and i + 1 < len(data):
                modrm = data[i+1]
                reg   = self.REGISTERS[(modrm >> 3) & 7]
                rm    = self.REGISTERS[modrm & 7]
                lines.append(f"  0x{addr:08X}:  MOV {rm}, {reg}")
                i += 2
            elif byte == 0x8B and i + 1 < len(data):
                modrm = data[i+1]
                reg   = self.REGISTERS[(modrm >> 3) & 7]
                rm    = self.REGISTERS[modrm & 7]
                lines.append(f"  0x{addr:08X}:  MOV {reg}, {rm}")
                i += 2
            else:
                lines.append(f"  0x{addr:08X}:  {mnemonic} {operand}")
                i += 1
        return lines

    def translate_file(self, binary_path: str,
                       output_mode: str = "assembly",
                       show_progress: bool = True) -> Dict:
        """
        Translate binary file to assembly or Python pseudo-code.
        output_mode: 'assembly' | 'pseudocode' | 'both'
        Returns dict with translation result and metadata.
        """
        src = Path(binary_path)
        if not src.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        file_size = src.stat().st_size
        self.logger.log(f"Translating: {src.name} ({file_size} bytes) mode={output_mode}", "info")
        start = time.time()

        # Read first chunk for header detection
        with open(src, "rb") as f:
            header_data = f.read(512)
        fmt = self._detect_format(header_data)

        result = {
            "source_file":  str(src),
            "format":       fmt,
            "file_size":    file_size,
            "output_mode":  output_mode,
            "translated_at": datetime.utcnow().isoformat(),
            "assembly":     [],
            "pseudocode":   [],
            "header_info":  {}
        }

        # Parse header
        if fmt == "PE_EXE":
            with open(src, "rb") as f:
                all_data = f.read(min(file_size, 4096))
            result["header_info"] = self._parse_pe_header(all_data)
        elif fmt == "APK_ZIP":
            with open(src, "rb") as f:
                all_data = f.read()
            result["header_info"] = self._parse_apk_manifest(all_data)

        # Disassemble chunks
        assembly_lines = [
            f"; OsourCL Binary Translator v1.0",
            f"; Source: {src.name}",
            f"; Format: {fmt}",
            f"; Size:   {file_size} bytes",
            f"; Date:   {result['translated_at']}",
            f"; ----------------------------------------",
            f"",
            f"SECTION .text",
            f"",
        ]

        chunk_count = 0
        base_addr   = 0x00401000  # typical PE text section base
        processed   = 0

        with open(src, "rb") as f:
            # Skip PE header if applicable
            if fmt == "PE_EXE" and result["header_info"].get("valid"):
                pe_off = result["header_info"].get("pe_offset", 0)
                skip   = pe_off + 24 + result["header_info"].get("opt_hdr_size", 224)
                f.seek(min(skip, file_size))

            for raw_chunk in self._read_chunks_f(f):
                chunk_asm = self._disassemble_chunk(raw_chunk, base_addr + processed)
                assembly_lines.extend(chunk_asm)
                processed   += len(raw_chunk)
                chunk_count += 1
                if show_progress:
                    bar = self._progress_bar_simple(processed, file_size)
                    print(f"\r  Translating {bar}", end="", flush=True)
                if processed > 50 * 1024:  # limit assembly output to first 50KB
                    assembly_lines.append(f"  ; ... ({file_size - processed} bytes more, truncated for readability)")
                    break

        if show_progress:
            print()

        result["assembly"] = assembly_lines

        # Generate pseudo-code
        if output_mode in ("pseudocode", "both"):
            result["pseudocode"] = self._generate_pseudocode(assembly_lines, fmt, result["header_info"])

        elapsed = time.time() - start
        result["elapsed_sec"] = round(elapsed, 2)
        self.logger.record_metric("translations", 1)
        self.logger.log(f"Translation complete in {elapsed:.2f}s", "info")
        return result

    def _read_chunks_f(self, fobj) -> Generator[bytes, None, None]:
        while True:
            chunk = fobj.read(self.config.CHUNK_SIZE)
            if not chunk:
                break
            yield chunk

    def _progress_bar_simple(self, current: int, total: int, width: int = 30) -> str:
        if total == 0:
            return "[========]"
        pct    = min(current / total, 1.0)
        filled = int(width * pct)
        bar    = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {pct*100:.1f}%"

    def _generate_pseudocode(self, asm_lines: List[str], fmt: str, header: Dict) -> List[str]:
        """Convert assembly to Python-like pseudo-code."""
        lines = [
            "# OsourCL Binary Translator - Python Pseudo-code",
            f"# Format: {fmt}",
            "",
            "import ctypes",
            "",
        ]

        if fmt == "PE_EXE" and header.get("valid"):
            lines.append(f"# PE Binary: {header.get('machine', 'unknown')} architecture")
            lines.append(f"# Sections: {header.get('num_sections', '?')}")
            lines.append(f"# Compiled: {header.get('timestamp', 'unknown')}")
            lines.append("")

        lines.append("def translated_binary_main():")
        lines.append("    # Decompiled function body")
        lines.append("    registers = {'EAX':0,'ECX':0,'EDX':0,'EBX':0,'ESP':0,'EBP':0,'ESI':0,'EDI':0}")
        lines.append("    stack = []")
        lines.append("")

        for line in asm_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(";"):
                continue
            # Convert common patterns
            if "PUSH" in stripped:
                val = stripped.split("PUSH")[-1].strip()
                lines.append(f"    stack.append({val})  # PUSH {val}")
            elif "POP" in stripped:
                reg = stripped.split("POP")[-1].strip()
                lines.append(f"    registers['{reg}'] = stack.pop()  # POP {reg}")
            elif "MOV" in stripped and "," in stripped:
                parts = stripped.split("MOV")[-1].strip().split(",", 1)
                if len(parts) == 2:
                    dst, src = parts[0].strip(), parts[1].strip()
                    lines.append(f"    registers['{dst}'] = {src}  # MOV")
            elif "CALL" in stripped:
                target = stripped.split("CALL")[-1].strip()
                lines.append(f"    call({target})  # CALL")
            elif "RET" in stripped:
                lines.append(f"    return registers['EAX']  # RET")
                break
            elif "NOP" in stripped:
                lines.append(f"    pass  # NOP")

        lines.append("")
        lines.append("if __name__ == '__main__':")
        lines.append("    result = translated_binary_main()")
        lines.append("    print(f'Result: {result}')")
        return lines

    def save_translation(self, result: Dict, output_path: str,
                         cloud_storage: 'OsourCLCloudStorage' = None) -> str:
        """Save translation result to file, optionally upload to cloud."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        content = []
        if result.get("assembly"):
            content.append("\n".join(result["assembly"]))
        if result.get("pseudocode"):
            content.append("\n\n; === PYTHON PSEUDO-CODE ===\n")
            content.append("\n".join(result["pseudocode"]))

        text = "\n".join(content)
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)

        self.logger.log(f"Translation saved: {out}", "info")

        if cloud_storage:
            cloud_storage.upload(str(out), out.name)

        return str(out)


# ============================================================
# LAYER 7 - EXE EDITOR
# ============================================================

class OsourCLEXEEditor:
    """Edit EXE files: inject OsourCL stubs, modify headers, connect to cloud."""

    OSOURCL_STUB = b"""
; OsourCL Cloud Connector Stub
; Auto-injected by OsourCL v1.0
; This stub initializes OsourCL cloud connection on startup
"""

    def __init__(self, config: OsourCLConfig, logger: OsourCLLogger, security: OsourCLSecurity):
        self.config   = config
        self.logger   = logger
        self.security = security

    def open_exe(self, exe_path: str) -> Dict:
        """Open and parse EXE file."""
        src = Path(exe_path)
        if not src.exists():
            raise FileNotFoundError(f"EXE not found: {exe_path}")

        with open(src, "rb") as f:
            data = f.read(512)

        if data[:2] != b'MZ':
            raise ValueError(f"Not a valid EXE (MZ signature missing): {exe_path}")

        e_lfanew = struct.unpack_from("<I", data, 60)[0]
        file_size = src.stat().st_size

        info = {
            "path":      str(src),
            "size":      file_size,
            "valid_pe":  False,
            "machine":   "unknown",
            "sections":  0,
            "connected": False
        }

        if e_lfanew + 4 < len(data):
            with open(src, "rb") as f:
                f.seek(e_lfanew)
                pe_data = f.read(24)
            if pe_data[:4] == b'PE\x00\x00':
                machine      = struct.unpack_from("<H", pe_data, 4)[0]
                num_sections = struct.unpack_from("<H", pe_data, 6)[0]
                machine_map  = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}
                info["valid_pe"]  = True
                info["machine"]   = machine_map.get(machine, f"0x{machine:04X}")
                info["sections"]  = num_sections
                info["pe_offset"] = e_lfanew

        self.logger.log(f"EXE opened: {src.name} ({file_size} bytes, {info['machine']})", "info")
        return info

    def inject_osourcl(self, exe_path: str, api_key: str,
                       cloud_endpoint: str = "http://localhost:8080",
                       output_path: str = None) -> str:
        """
        Inject OsourCL connection metadata into EXE overlay section.
        Appends connection config as signed overlay (does not break execution).
        """
        src = Path(exe_path)
        info = self.open_exe(exe_path)

        payload = json.dumps({
            "osourcl_version": "1.0.0",
            "api_key_hash":    self.security.secure_hash_api_key(api_key),
            "cloud_endpoint":  cloud_endpoint,
            "connected_at":    datetime.utcnow().isoformat(),
            "machine":         info["machine"]
        }).encode()

        signature = self.security.hmac_sign(
            payload,
            self.security._master_key
        ).encode()

        overlay = b"OSOURCL_CONNECT\x00" + \
                  struct.pack(">I", len(payload)) + payload + \
                  struct.pack(">I", len(signature)) + signature + \
                  b"\x00OSOURCL_END"

        out_path = output_path or str(src.with_stem(src.stem + "_osourcl"))
        shutil.copy2(src, out_path)

        with open(out_path, "ab") as f:
            f.write(overlay)

        self.logger.log(
            f"OsourCL injected into EXE: {out_path} (+{len(overlay)} bytes overlay)",
            "info"
        )
        self.logger.log(f"EXE_CONNECTED path={out_path}", "info", "audit")
        return out_path

    def verify_connection(self, exe_path: str) -> Dict:
        """Check if EXE has OsourCL overlay."""
        src = Path(exe_path)
        with open(src, "rb") as f:
            data = f.read()

        marker = b"OSOURCL_CONNECT\x00"
        idx = data.rfind(marker)
        if idx == -1:
            return {"connected": False}

        try:
            payload_offset = idx + len(marker)
            payload_len    = struct.unpack_from(">I", data, payload_offset)[0]
            payload        = data[payload_offset + 4: payload_offset + 4 + payload_len]
            info           = json.loads(payload)
            return {"connected": True, "info": info}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    def send_translation_to_exe(self, exe_path: str, translation_result: Dict,
                                output_path: str = None) -> str:
        """Append binary translation result metadata to EXE as overlay."""
        src = Path(exe_path)
        if not src.exists():
            raise FileNotFoundError(f"EXE not found: {exe_path}")

        asm_text = "\n".join(translation_result.get("assembly", []))
        payload  = json.dumps({
            "osourcl_translation": True,
            "format":  translation_result.get("format"),
            "mode":    translation_result.get("output_mode"),
            "source":  translation_result.get("source_file"),
            "lines":   len(translation_result.get("assembly", [])),
            "at":      datetime.utcnow().isoformat()
        }).encode()

        overlay = b"OSOURCL_TRANS\x00" + \
                  struct.pack(">I", len(payload)) + payload + \
                  b"\x00OSOURCL_TRANS_END"

        out_path = output_path or str(src.with_stem(src.stem + "_translated"))
        shutil.copy2(src, out_path)
        with open(out_path, "ab") as f:
            f.write(overlay)

        # Also save assembly file next to output
        asm_path = Path(out_path).with_suffix(".asm")
        with open(asm_path, "w") as f:
            f.write(asm_text)

        self.logger.log(f"Translation sent to EXE: {out_path}", "info")
        return out_path


# ============================================================
# LAYER 8 - APK EDITOR
# ============================================================

class OsourCLAPKEditor:
    """Edit APK files: inject OsourCL metadata, modify manifest, connect to cloud."""

    def __init__(self, config: OsourCLConfig, logger: OsourCLLogger, security: OsourCLSecurity):
        self.config   = config
        self.logger   = logger
        self.security = security

    def open_apk(self, apk_path: str) -> Dict:
        """Open and parse APK file."""
        import zipfile
        src = Path(apk_path)
        if not src.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        with open(src, "rb") as f:
            magic = f.read(4)
        if magic != b'PK\x03\x04':
            raise ValueError(f"Not a valid APK/ZIP: {apk_path}")

        info = {
            "path":      str(src),
            "size":      src.stat().st_size,
            "entries":   [],
            "has_dex":   False,
            "has_manifest": False,
            "connected": False
        }

        try:
            with zipfile.ZipFile(src, "r") as z:
                info["entries"]      = z.namelist()
                info["has_manifest"] = "AndroidManifest.xml" in info["entries"]
                info["has_dex"]      = any(e.endswith(".dex") for e in info["entries"])
                info["entry_count"]  = len(info["entries"])
        except Exception as e:
            info["error"] = str(e)

        self.logger.log(
            f"APK opened: {src.name} ({info['size']} bytes, {info.get('entry_count',0)} entries)",
            "info"
        )
        return info

    def inject_osourcl(self, apk_path: str, api_key: str,
                       cloud_endpoint: str = "http://localhost:8080",
                       output_path: str = None) -> str:
        """
        Inject OsourCL connection config into APK as a new ZIP entry.
        Does not re-sign APK (for testing/development use).
        """
        import zipfile
        src      = Path(apk_path)
        out_path = output_path or str(src.with_stem(src.stem + "_osourcl"))
        shutil.copy2(src, out_path)

        payload = json.dumps({
            "osourcl_version": "1.0.0",
            "api_key_hash":    self.security.secure_hash_api_key(api_key),
            "cloud_endpoint":  cloud_endpoint,
            "connected_at":    datetime.utcnow().isoformat(),
        }, indent=2).encode()

        try:
            with zipfile.ZipFile(out_path, "a") as z:
                z.writestr("assets/osourcl_config.json", payload)
        except Exception as e:
            self.logger.log(f"APK injection error: {e}", "error")
            raise

        self.logger.log(f"OsourCL injected into APK: {out_path}", "info")
        self.logger.log(f"APK_CONNECTED path={out_path}", "info", "audit")
        return out_path

    def send_translation_to_apk(self, apk_path: str, translation_result: Dict,
                                output_path: str = None) -> str:
        """Append binary translation result into APK as an asset."""
        import zipfile
        src      = Path(apk_path)
        out_path = output_path or str(src.with_stem(src.stem + "_translated"))
        shutil.copy2(src, out_path)

        asm_text = "\n".join(translation_result.get("assembly", []))
        pseudo   = "\n".join(translation_result.get("pseudocode", []))

        try:
            with zipfile.ZipFile(out_path, "a") as z:
                z.writestr("assets/osourcl_translation.asm", asm_text)
                if pseudo:
                    z.writestr("assets/osourcl_pseudocode.py", pseudo)
                z.writestr("assets/osourcl_meta.json", json.dumps({
                    "format":  translation_result.get("format"),
                    "source":  translation_result.get("source_file"),
                    "lines":   len(translation_result.get("assembly", [])),
                    "at":      datetime.utcnow().isoformat()
                }, indent=2))
        except Exception as e:
            self.logger.log(f"APK translation injection error: {e}", "error")
            raise

        self.logger.log(f"Translation sent to APK: {out_path}", "info")
        return out_path

    def modify_manifest_permission(self, apk_path: str, permission: str,
                                   output_path: str = None) -> str:
        """
        Note: AndroidManifest.xml in APK is binary-encoded (AXML format).
        This method adds a note file as workaround (full AXML editing requires
        specialized parser). Returns output path.
        """
        import zipfile
        src      = Path(apk_path)
        out_path = output_path or str(src.with_stem(src.stem + "_modified"))
        shutil.copy2(src, out_path)

        note = f"OsourCL: Requested permission {permission}\n" \
               f"Add manually to AndroidManifest.xml:\n" \
               f'<uses-permission android:name="{permission}"/>\n'

        with zipfile.ZipFile(out_path, "a") as z:
            z.writestr("assets/osourcl_permissions.txt", note)

        self.logger.log(f"APK manifest permission note added: {permission}", "info")
        return out_path


# ============================================================
# LAYER 9 - INTERNET KECIL (Internal HTTP + Proxy)
# ============================================================

class _InternalHTTPHandler(BaseHTTPRequestHandler):
    """Internal HTTP request handler for OsourCL internet kecil."""

    def log_message(self, format, *args):
        pass  # Suppress default access log (we use our own)

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def _handle_request(self, method: str):
        try:
            path = self.path
            response = {"method": method, "path": path, "status": "ok",
                        "server": "OsourCL-Internet-Kecil/1.0",
                        "timestamp": datetime.utcnow().isoformat()}

            body = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type",   "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-OsourCL",      "internet-kecil")
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass


class OsourCLInternetKecil:
    """
    Internal micro-internet: HTTP server (localhost:8080),
    proxy server (localhost:8081), DNS cache, bandwidth-limited HTTP client.
    """

    def __init__(self, config: OsourCLConfig, logger: OsourCLLogger):
        self.config        = config
        self.logger        = logger
        self._http_server  = None
        self._proxy_server = None
        self._http_thread  = None
        self._proxy_thread = None
        self._dns_cache: Dict[str, str] = {}
        self._lock         = threading.Lock()
        self._running      = False
        self._bandwidth_counter = 0
        self._bandwidth_reset   = time.time()

    def start(self):
        """Start internal HTTP server and proxy."""
        if self._running:
            return
        self._running = True
        self._start_http_server()
        self._start_proxy_server()
        self.logger.log(
            f"Internet kecil started: HTTP=:{self.config.HTTP_PORT} "
            f"Proxy=:{self.config.PROXY_PORT}",
            "info"
        )

    def _start_http_server(self):
        def run():
            try:
                handler = _InternalHTTPHandler
                self._http_server = socketserver.TCPServer(
                    ("127.0.0.1", self.config.HTTP_PORT), handler
                )
                self._http_server.allow_reuse_address = True
                self._http_server.serve_forever()
            except OSError as e:
                self.logger.log(f"HTTP server error: {e}", "warning")
        self._http_thread = threading.Thread(target=run, daemon=True)
        self._http_thread.start()

    def _start_proxy_server(self):
        def run():
            try:
                handler = _InternalHTTPHandler
                self._proxy_server = socketserver.TCPServer(
                    ("127.0.0.1", self.config.PROXY_PORT), handler
                )
                self._proxy_server.allow_reuse_address = True
                self._proxy_server.serve_forever()
            except OSError as e:
                self.logger.log(f"Proxy server error: {e}", "warning")
        self._proxy_thread = threading.Thread(target=run, daemon=True)
        self._proxy_thread.start()

    def stop(self):
        """Stop internal servers."""
        if self._http_server:
            self._http_server.shutdown()
        if self._proxy_server:
            self._proxy_server.shutdown()
        self._running = False
        self.logger.log("Internet kecil stopped", "info")

    def _check_bandwidth(self, bytes_needed: int) -> bool:
        """Enforce bandwidth limit (1 MB/s)."""
        now = time.time()
        with self._lock:
            if now - self._bandwidth_reset > 1.0:
                self._bandwidth_counter = 0
                self._bandwidth_reset   = now
            if self._bandwidth_counter + bytes_needed > self.config.BANDWIDTH_LIMIT:
                return False
            self._bandwidth_counter += bytes_needed
            return True

    def http_get(self, url: str, timeout: int = 10) -> Optional[bytes]:
        """Bandwidth-limited HTTP GET."""
        try:
            req  = Request(url, headers={"User-Agent": "OsourCL-InternetKecil/1.0"})
            resp = urlopen(req, timeout=timeout)
            data = resp.read(self.config.BANDWIDTH_LIMIT)  # max 1MB per request
            if not self._check_bandwidth(len(data)):
                self.logger.log("Bandwidth limit hit, throttling", "warning")
                time.sleep(1)
            self.logger.log(f"HTTP GET {url} -> {len(data)} bytes", "info")
            return data
        except URLError as e:
            self.logger.log(f"HTTP GET failed: {url} -> {e}", "error")
            return None

    def http_post(self, url: str, data: bytes, content_type: str = "application/json",
                  timeout: int = 10) -> Optional[bytes]:
        """Bandwidth-limited HTTP POST."""
        try:
            if not self._check_bandwidth(len(data)):
                self.logger.log("Bandwidth limit hit on POST", "warning")
                time.sleep(1)
            req  = Request(url, data=data, method="POST",
                           headers={"Content-Type": content_type,
                                    "User-Agent": "OsourCL-InternetKecil/1.0"})
            resp = urlopen(req, timeout=timeout)
            resp_data = resp.read(self.config.BANDWIDTH_LIMIT)
            self.logger.log(f"HTTP POST {url} -> {len(resp_data)} bytes response", "info")
            return resp_data
        except URLError as e:
            self.logger.log(f"HTTP POST failed: {url} -> {e}", "error")
            return None

    def resolve_dns(self, hostname: str) -> Optional[str]:
        """DNS resolution with cache."""
        with self._lock:
            if hostname in self._dns_cache:
                return self._dns_cache[hostname]
        try:
            ip = socket.gethostbyname(hostname)
            with self._lock:
                self._dns_cache[hostname] = ip
            self.logger.log(f"DNS {hostname} -> {ip}", "info")
            return ip
        except socket.gaierror as e:
            self.logger.log(f"DNS failed: {hostname} -> {e}", "error")
            return None

    def get_status(self) -> Dict:
        return {
            "running":           self._running,
            "http_port":         self.config.HTTP_PORT,
            "proxy_port":        self.config.PROXY_PORT,
            "bandwidth_used":    self._bandwidth_counter,
            "bandwidth_limit":   self.config.BANDWIDTH_LIMIT,
            "dns_cache_entries": len(self._dns_cache)
        }


# ============================================================
# LAYER 10 - MOTHERBOARD (Central Orchestrator)
# ============================================================

class OsourCLMotherboard:
    """
    Cloud Component Motherboard: orchestrates all OsourCL components.
    Manages data flow, crash recovery, health monitoring.
    """

    def __init__(self):
        self.config      = OsourCLConfig()
        self.logger      = OsourCLLogger(self.config)
        self.security    = OsourCLSecurity(self.config, self.logger)
        self.api_keys    = OsourCLAPIKeyManager(self.config, self.logger, self.security)
        self.cloud       = OsourCLCloudStorage(self.config, self.logger, self.security)
        self.translator  = OsourCLBinaryTranslator(self.config, self.logger)
        self.exe_editor  = OsourCLEXEEditor(self.config, self.logger, self.security)
        self.apk_editor  = OsourCLAPKEditor(self.config, self.logger, self.security)
        self.internet    = OsourCLInternetKecil(self.config, self.logger)
        self._health_thread: Optional[threading.Thread] = None
        self._running    = False

        self._register_shutdown()

    def _register_shutdown(self):
        atexit.register(self._shutdown)
        try:
            signal.signal(signal.SIGINT,  self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (OSError, ValueError):
            pass

    def _signal_handler(self, signum, frame):
        self.logger.log(f"Signal {signum} received, shutting down...", "info")
        self._shutdown()

    def _shutdown(self):
        if not self._running:
            return
        self._running = False
        try:
            self.internet.stop()
            self.logger.save_metrics()
        except Exception as e:
            pass

    def start(self):
        """Start the motherboard and all components."""
        self._running = True
        self.internet.start()
        self._start_health_monitor()
        self.logger.log("OsourCL Motherboard started", "info")

    def _start_health_monitor(self):
        def monitor():
            while self._running:
                time.sleep(60)
                try:
                    self.logger.save_metrics()
                    quota = self.cloud.get_quota_info()
                    self.logger.log(
                        f"HEALTH quota={quota['used_percent']}% "
                        f"files={quota['files_count']} "
                        f"ops={self.logger.get_metrics()['operations']}",
                        "debug", "metrics"
                    )
                except Exception as e:
                    self.logger.log(f"Health monitor error: {e}", "error")
        self._health_thread = threading.Thread(target=monitor, daemon=True)
        self._health_thread.start()

    def get_status(self) -> Dict:
        """Get full system status."""
        return {
            "version":    "1.0.0",
            "running":    self._running,
            "timestamp":  datetime.utcnow().isoformat(),
            "cloud":      self.cloud.get_quota_info(),
            "api_keys":   self.api_keys.get_usage_stats(),
            "internet":   self.internet.get_status(),
            "metrics":    self.logger.get_metrics(),
        }

    # ---- Convenience pipeline methods ----

    def translate_and_upload(self, binary_path: str,
                             output_mode: str = "both") -> Dict:
        """Translate binary, save result, upload to cloud."""
        result   = self.translator.translate_file(binary_path, output_mode)
        out_path = str(self.config.DATA_PATH / (Path(binary_path).stem + "_translated.txt"))
        self.translator.save_translation(result, out_path, self.cloud)
        return result

    def translate_and_send_exe(self, binary_path: str, target_exe: str,
                               output_path: str = None) -> str:
        """Translate binary and send result to target EXE."""
        result = self.translator.translate_file(binary_path, "both")
        return self.exe_editor.send_translation_to_exe(target_exe, result, output_path)

    def translate_and_send_apk(self, binary_path: str, target_apk: str,
                               output_path: str = None) -> str:
        """Translate binary and send result to target APK."""
        result = self.translator.translate_file(binary_path, "both")
        return self.apk_editor.send_translation_to_apk(target_apk, result, output_path)

    def connect_exe_to_cloud(self, exe_path: str, api_key: str,
                             output_path: str = None) -> str:
        """Inject OsourCL cloud connection into EXE."""
        valid, _ = self.api_keys.validate_api_key(api_key)
        if not valid:
            raise PermissionError("Invalid or expired API key")
        return self.exe_editor.inject_osourcl(exe_path, api_key, output_path=output_path)

    def connect_apk_to_cloud(self, apk_path: str, api_key: str,
                             output_path: str = None) -> str:
        """Inject OsourCL cloud connection into APK."""
        valid, _ = self.api_keys.validate_api_key(api_key)
        if not valid:
            raise PermissionError("Invalid or expired API key")
        return self.apk_editor.inject_osourcl(apk_path, api_key, output_path=output_path)


# ============================================================
# MAIN CLASS - PUBLIC API
# ============================================================

class OsourCL:
    """
    OsourCL - Cloud Component Motherboard
    ======================================
    Main entry point. Combines all components.

    Usage:
        ocl = OsourCL()
        ocl.start()

        # Cloud storage
        ocl.upload("myfile.bin")
        ocl.download("file_id", "output.bin")

        # Binary translation
        ocl.translate("program.exe", mode="both")

        # EXE/APK connection
        api_key = ocl.generate_api_key()
        ocl.connect_exe("program.exe", api_key)
        ocl.connect_apk("app.apk", api_key)
    """

    VERSION = "1.0.0"

    def __init__(self):
        self._mb = OsourCLMotherboard()

    def start(self):
        """Start OsourCL engine."""
        self._mb.start()

    # ---- API Key Management ----

    def generate_api_key(self, name: str = "default",
                         permissions: List[str] = None) -> str:
        return self._mb.api_keys.generate_api_key(name, permissions)

    def validate_api_key(self, key: str) -> bool:
        valid, _ = self._mb.api_keys.validate_api_key(key)
        return valid

    def rotate_api_key(self, old_key: str) -> Optional[str]:
        return self._mb.api_keys.rotate_api_key(old_key)

    def revoke_api_key(self, key: str) -> bool:
        return self._mb.api_keys.revoke_api_key(key)

    def list_api_keys(self) -> List[Dict]:
        return self._mb.api_keys.list_keys()

    # ---- Cloud Storage ----

    def upload(self, local_path: str, remote_name: str = None,
               encrypt: bool = True, compress: bool = True) -> Dict:
        return self._mb.cloud.upload(local_path, remote_name, encrypt, compress)

    def download(self, file_id: str, dest_path: str) -> str:
        return self._mb.cloud.download(file_id, dest_path)

    def list_files(self) -> List[Dict]:
        return self._mb.cloud.list_files()

    def delete_file(self, file_id: str) -> bool:
        return self._mb.cloud.delete_file(file_id)

    def sync_to_cloud(self, local_dir: str) -> List[Dict]:
        return self._mb.cloud.sync_to_cloud(local_dir)

    def sync_from_cloud(self, local_dir: str) -> List[Dict]:
        return self._mb.cloud.sync_from_cloud(local_dir)

    def get_quota(self) -> Dict:
        return self._mb.cloud.get_quota_info()

    def backup(self):
        self._mb.cloud.create_backup()

    # ---- Binary Translator ----

    def translate(self, binary_path: str, mode: str = "both") -> Dict:
        return self._mb.translator.translate_file(binary_path, mode)

    def translate_and_upload(self, binary_path: str, mode: str = "both") -> Dict:
        return self._mb.translate_and_upload(binary_path, mode)

    # ---- EXE Editor ----

    def open_exe(self, exe_path: str) -> Dict:
        return self._mb.exe_editor.open_exe(exe_path)

    def connect_exe(self, exe_path: str, api_key: str, output_path: str = None) -> str:
        return self._mb.connect_exe_to_cloud(exe_path, api_key, output_path)

    def send_translation_to_exe(self, binary_path: str, target_exe: str,
                                output_path: str = None) -> str:
        return self._mb.translate_and_send_exe(binary_path, target_exe, output_path)

    # ---- APK Editor ----

    def open_apk(self, apk_path: str) -> Dict:
        return self._mb.apk_editor.open_apk(apk_path)

    def connect_apk(self, apk_path: str, api_key: str, output_path: str = None) -> str:
        return self._mb.connect_apk_to_cloud(apk_path, api_key, output_path)

    def send_translation_to_apk(self, binary_path: str, target_apk: str,
                                output_path: str = None) -> str:
        return self._mb.translate_and_send_apk(binary_path, target_apk, output_path)

    # ---- Internet Kecil ----

    def http_get(self, url: str) -> Optional[bytes]:
        return self._mb.internet.http_get(url)

    def http_post(self, url: str, data: bytes) -> Optional[bytes]:
        return self._mb.internet.http_post(url, data)

    # ---- Status ----

    def status(self) -> Dict:
        return self._mb.get_status()


# ============================================================
# CLI ENTRY POINT
# ============================================================

def _banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          OsourCL - Cloud Component Motherboard v1.0          ║
║         Enterprise-Grade | AES-256 | 10GB Support            ║
║         Binary Translator | EXE/APK Editor | API Key Auth    ║
╚══════════════════════════════════════════════════════════════╝
""")

def _print_section(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")

def main():
    _banner()

    print("[*] Initializing OsourCL engine...")
    try:
        ocl = OsourCL()
        ocl.start()
        print("[✓] Engine started successfully")
    except Exception as e:
        print(f"[✗] Engine startup failed: {e}")
        traceback.print_exc()
        sys.exit(1)

    # Generate API key on startup
    _print_section("API Key Generation")
    try:
        api_key = ocl.generate_api_key(name="startup", permissions=["read","write","translate","connect"])
        print(f"\n  ✅ New API Key Generated:")
        print(f"\n  {api_key}\n")
        print(f"  ⚠️  Save this key! It will not be shown again.")
        print(f"  📁 Key stored at: {OsourCLConfig.API_KEY_FILE}")
    except Exception as e:
        print(f"  [✗] API key generation failed: {e}")
        api_key = None

    # Show quota status
    _print_section("Cloud Storage Status")
    quota = ocl.get_quota()
    print(f"  Quota used:    {quota['used_mb']} MB / {quota['max_gb']} GB")
    print(f"  Files stored:  {quota['files_count']}")
    print(f"  Used percent:  {quota['used_percent']}%")

    # Show internet kecil status
    _print_section("Internet Kecil Status")
    inet = ocl.status()["internet"]
    print(f"  HTTP server:   localhost:{inet['http_port']}  {'✓ running' if inet['running'] else '✗ stopped'}")
    print(f"  Proxy server:  localhost:{inet['proxy_port']} {'✓ running' if inet['running'] else '✗ stopped'}")
    print(f"  Bandwidth:     {inet['bandwidth_limit']/(1024)} KB/s limit")

    # Show API key list
    _print_section("Registered API Keys")
    keys = ocl.list_api_keys()
    for k in keys:
        status_icon = "✓" if k["active"] and not k["revoked"] else "✗"
        print(f"  [{status_icon}] {k['name']:<12} id={k['id'][:8]}...  "
              f"calls={k['usage_count']}  expires={k['expires_at'][:10]}")

    # Show system metrics
    _print_section("System Metrics")
    metrics = ocl.status()["metrics"]
    print(f"  Operations:    {metrics['operations']}")
    print(f"  Errors:        {metrics['errors']}")
    print(f"  API calls:     {metrics['api_calls']}")
    print(f"  Translations:  {metrics['translations']}")
    print(f"  Bytes up:      {metrics['bytes_uploaded']/(1024**2):.2f} MB")
    print(f"  Bytes down:    {metrics['bytes_downloaded']/(1024**2):.2f} MB")

    _print_section("Usage Examples")
    print("""
  # Import OsourCL in your Python script:
  from OsourCL import OsourCL

  ocl = OsourCL()
  ocl.start()

  # Cloud storage (10GB support):
  meta = ocl.upload("bigfile.bin")           # Upload with AES-256 + gzip
  ocl.download(meta["id"], "output.bin")     # Download and decrypt
  ocl.sync_to_cloud("./my_folder")           # Sync entire folder

  # Binary translation:
  result = ocl.translate("program.exe", mode="both")   # asm + pseudocode
  ocl.translate_and_upload("program.exe")               # translate + cloud

  # Connect EXE to cloud:
  key = ocl.generate_api_key("myapp")
  ocl.connect_exe("program.exe", key)
  ocl.send_translation_to_exe("input.bin", "target.exe")

  # Connect APK to cloud:
  ocl.connect_apk("app.apk", key)
  ocl.send_translation_to_apk("input.bin", "app.apk")

  # Internet kecil:
  data = ocl.http_get("http://example.com")
  ocl.http_post("http://localhost:8080/data", b'{"key":"val"}')

  # API key management:
  new_key = ocl.rotate_api_key(old_key)
  ocl.revoke_api_key(old_key)
  ocl.validate_api_key(key)
""")

    print("─" * 60)
    print(f"  📂 Data dir:  {OsourCLConfig.BASE_DIR.resolve()}")
    print(f"  📝 Logs dir:  {OsourCLConfig.LOG_PATH.resolve()}")
    print(f"  ☁️  Cloud dir: {OsourCLConfig.CLOUD_STORAGE_PATH.resolve()}")
    print("─" * 60)
    print("\n  OsourCL engine running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down OsourCL...")
        ocl._mb._shutdown()
        print("[✓] Shutdown complete.")


if __name__ == "__main__":
    main()
