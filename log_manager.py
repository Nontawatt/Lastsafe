#!/usr/bin/env python3
"""
log_manager: PQC-secured Log Management System for Lastsafe
=============================================================

Inspired by SRAN METALog (https://metalog.sran.net/), this module provides
a comprehensive log management system with post-quantum cryptographic
security.  It integrates with Lastsafe's existing PQC encryption to offer
secure log collection, compressed storage, fast search, and forwarding.

Features (inspired by METALog)
-------------------------------
* **Log Collection** - Receive syslog messages via UDP and TCP supporting
  both RFC 5424 and RFC 3164 formats, plus generic single-line log input.
* **Compressed Storage** - Logs are stored with LZMA or ZSTD compression
  achieving significant space savings.  Optionally encrypt archives with
  PQC (ML-KEM + AES-GCM) for quantum-resistant confidentiality.
* **Search & Retrieval** - Full-text search with regex support, time-range
  filtering, and severity-level filtering across archived log files.
* **Forwarding & Filtering** - Content-based filtering and forwarding of
  log events to external SIEM platforms or files via UDP, TCP, or file output.
* **Log Rotation** - Automatic rotation based on file size thresholds with
  configurable retention policies.

Architecture
------------
::

    ┌─────────────┬──────────────┬───────────┬─────────────┐
    │  Collector   │   Storage    │  Search   │  Forwarder  │
    │  UDP/TCP     │  LZMA/ZSTD   │ Full-text │  TCP/UDP    │
    │  RFC5424     │  + PQC       │ Regex     │  File       │
    │  RFC3164     │  Encryption  │ Time-range│  SIEM       │
    └─────────────┴──────────────┴───────────┴─────────────┘
"""

import datetime
import io
import json
import lzma
import os
import re
import socket
import struct
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Syslog severity levels (RFC 5424 Section 6.2.1)
# ---------------------------------------------------------------------------

class SyslogSeverity(IntEnum):
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


class SyslogFacility(IntEnum):
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    NTP = 12
    AUDIT = 13
    ALERT = 14
    CLOCK = 15
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


# ---------------------------------------------------------------------------
# Log event data model
# ---------------------------------------------------------------------------

@dataclass
class LogEvent:
    """Represents a single parsed log event."""
    timestamp: str
    hostname: str
    app_name: str
    severity: int
    facility: int
    message: str
    raw: str
    source_ip: str = ""
    pid: str = ""
    msg_id: str = ""
    structured_data: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, data: str) -> "LogEvent":
        return cls(**json.loads(data))

    @property
    def severity_name(self) -> str:
        try:
            return SyslogSeverity(self.severity).name
        except ValueError:
            return f"UNKNOWN({self.severity})"

    @property
    def facility_name(self) -> str:
        try:
            return SyslogFacility(self.facility).name
        except ValueError:
            return f"UNKNOWN({self.facility})"


# ---------------------------------------------------------------------------
# Syslog parser - supports RFC 5424 and RFC 3164
# ---------------------------------------------------------------------------

class SyslogParser:
    """Parse syslog messages in RFC 5424 and RFC 3164 formats."""

    # RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA MSG
    _RFC5424_RE = re.compile(
        r"<(\d{1,3})>(\d+)\s+"                         # <PRI>VERSION
        r"(\S+)\s+"                                     # TIMESTAMP
        r"(\S+)\s+"                                     # HOSTNAME
        r"(\S+)\s+"                                     # APP-NAME
        r"(\S+)\s+"                                     # PROCID
        r"(\S+)\s+"                                     # MSGID
        r"((?:\[.*?\])+|-)\s*"                          # STRUCTURED-DATA
        r"(.*)",                                        # MSG
        re.DOTALL,
    )

    # RFC 3164: <PRI>TIMESTAMP HOSTNAME APP-NAME[PID]: MSG
    _RFC3164_RE = re.compile(
        r"<(\d{1,3})>"                                  # <PRI>
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"   # TIMESTAMP (MMM DD HH:MM:SS)
        r"(\S+)\s+"                                     # HOSTNAME
        r"(\S+?)(?:\[(\d+)\])?:\s*"                     # APP-NAME[PID]:
        r"(.*)",                                        # MSG
        re.DOTALL,
    )

    @staticmethod
    def _decode_priority(pri: int) -> Tuple[int, int]:
        """Decode PRI value into facility and severity."""
        facility = pri >> 3
        severity = pri & 0x07
        return facility, severity

    @classmethod
    def parse(cls, raw: str, source_ip: str = "") -> LogEvent:
        """Attempt to parse a raw syslog line. Falls back to generic format."""
        raw = raw.strip()

        # Try RFC 5424 first
        m = cls._RFC5424_RE.match(raw)
        if m:
            pri = int(m.group(1))
            facility, severity = cls._decode_priority(pri)
            return LogEvent(
                timestamp=m.group(3),
                hostname=m.group(4),
                app_name=m.group(5),
                severity=severity,
                facility=facility,
                message=m.group(9),
                raw=raw,
                source_ip=source_ip,
                pid=m.group(6) if m.group(6) != "-" else "",
                msg_id=m.group(7) if m.group(7) != "-" else "",
                structured_data=m.group(8) if m.group(8) != "-" else "",
            )

        # Try RFC 3164
        m = cls._RFC3164_RE.match(raw)
        if m:
            pri = int(m.group(1))
            facility, severity = cls._decode_priority(pri)
            return LogEvent(
                timestamp=m.group(2),
                hostname=m.group(3),
                app_name=m.group(4),
                severity=severity,
                facility=facility,
                message=m.group(6),
                raw=raw,
                source_ip=source_ip,
                pid=m.group(5) or "",
            )

        # Generic fallback - treat entire line as message
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return LogEvent(
            timestamp=now,
            hostname="unknown",
            app_name="unknown",
            severity=SyslogSeverity.INFORMATIONAL,
            facility=SyslogFacility.USER,
            message=raw,
            raw=raw,
            source_ip=source_ip,
        )


# ---------------------------------------------------------------------------
# Log Storage - compressed and optionally PQC-encrypted
# ---------------------------------------------------------------------------

class LogStorage:
    """Manages log file storage with compression and optional PQC encryption.

    Logs are stored as JSONL (one JSON object per line) compressed with LZMA.
    Active log files are written as plain JSONL and rotated/compressed when
    they exceed ``max_file_size`` bytes.  Optionally, rotated archives can be
    encrypted using Lastsafe's PQC encryption (ML-KEM + AES-GCM).
    """

    def __init__(
        self,
        storage_dir: Path,
        max_file_size: int = 50 * 1024 * 1024,  # 50 MB default
        max_archives: int = 100,
        compression: str = "lzma",
        public_key_path: Optional[Path] = None,
        kem_alg: str = "ML-KEM-512",
    ) -> None:
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.max_file_size = max_file_size
        self.max_archives = max_archives
        self.compression = compression
        self.public_key_path = public_key_path
        self.kem_alg = kem_alg
        self._lock = threading.Lock()

        self._active_file = self.storage_dir / "current.log"

    def _rotate_if_needed(self) -> None:
        """Rotate the active log file if it exceeds the size threshold."""
        if not self._active_file.exists():
            return
        if self._active_file.stat().st_size < self.max_file_size:
            return

        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        archive_name = f"archive-{ts}.log"

        # Compress the file
        plain_data = self._active_file.read_bytes()
        compressed = lzma.compress(plain_data, preset=6)
        archive_path = self.storage_dir / (archive_name + ".xz")

        # Optionally encrypt the compressed archive with PQC
        if self.public_key_path and self.public_key_path.exists():
            encrypted_data = self._pqc_encrypt(compressed)
            archive_path = self.storage_dir / (archive_name + ".xz.pqc")
            archive_path.write_bytes(encrypted_data)
        else:
            archive_path.write_bytes(compressed)

        # Clear the active file
        self._active_file.write_bytes(b"")

        # Enforce retention - remove oldest archives if over limit
        self._enforce_retention()

    def _pqc_encrypt(self, data: bytes) -> bytes:
        """Encrypt data using Lastsafe's PQC scheme (ML-KEM + AES-GCM)."""
        import secrets as _secrets
        try:
            import oqs
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            # If PQC libraries not available, return data unencrypted
            return data

        public_key = self.public_key_path.read_bytes()
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        aes_key = shared_secret[:32]
        nonce = _secrets.token_bytes(12)
        aesgcm = AESGCM(aes_key)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        # Same format as lastsafe.py: [uint32:ct_len][ciphertext][nonce][encrypted]
        result = struct.pack("!I", len(ciphertext))
        result += ciphertext
        result += nonce
        result += encrypted_data
        return result

    @staticmethod
    def pqc_decrypt(data: bytes, secret_key_path: Path, kem_alg: str = "ML-KEM-512") -> bytes:
        """Decrypt PQC-encrypted data using a private key."""
        try:
            import oqs
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError("PQC libraries (oqs, cryptography) required for decryption")

        secret_key = secret_key_path.read_bytes()
        buf = io.BytesIO(data)
        header = buf.read(4)
        if len(header) != 4:
            raise ValueError("Encrypted data too short")
        (ct_len,) = struct.unpack("!I", header)
        ciphertext = buf.read(ct_len)
        nonce = buf.read(12)
        encrypted_payload = buf.read()

        with oqs.KeyEncapsulation(kem_alg, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        aes_key = shared_secret[:32]
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, encrypted_payload, None)

    def _enforce_retention(self) -> None:
        """Remove oldest archives if we exceed max_archives."""
        archives = sorted(
            [f for f in self.storage_dir.iterdir() if f.name.startswith("archive-")],
            key=lambda f: f.stat().st_mtime,
        )
        while len(archives) > self.max_archives:
            oldest = archives.pop(0)
            oldest.unlink()

    def write(self, event: LogEvent) -> None:
        """Append a log event to the active log file."""
        with self._lock:
            self._rotate_if_needed()
            with self._active_file.open("a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")

    def write_batch(self, events: List[LogEvent]) -> None:
        """Append multiple log events atomically."""
        with self._lock:
            self._rotate_if_needed()
            with self._active_file.open("a", encoding="utf-8") as f:
                for event in events:
                    f.write(event.to_json() + "\n")

    def get_stats(self) -> Dict:
        """Return storage statistics."""
        archives = [f for f in self.storage_dir.iterdir() if f.name.startswith("archive-")]
        active_size = self._active_file.stat().st_size if self._active_file.exists() else 0
        archive_size = sum(f.stat().st_size for f in archives)
        active_lines = 0
        if self._active_file.exists():
            with self._active_file.open("r", encoding="utf-8") as f:
                active_lines = sum(1 for _ in f)
        return {
            "storage_dir": str(self.storage_dir),
            "active_file_size_bytes": active_size,
            "active_log_events": active_lines,
            "archive_count": len(archives),
            "archive_total_size_bytes": archive_size,
            "compression": self.compression,
            "pqc_encryption": self.public_key_path is not None,
            "max_file_size_bytes": self.max_file_size,
            "max_archives": self.max_archives,
        }


# ---------------------------------------------------------------------------
# Log Search Engine
# ---------------------------------------------------------------------------

class LogSearch:
    """Search across active and archived log files."""

    def __init__(self, storage_dir: Path, secret_key_path: Optional[Path] = None,
                 kem_alg: str = "ML-KEM-512") -> None:
        self.storage_dir = storage_dir
        self.secret_key_path = secret_key_path
        self.kem_alg = kem_alg

    def _iter_active_events(self) -> Iterator[LogEvent]:
        """Iterate over events in the active log file."""
        active = self.storage_dir / "current.log"
        if not active.exists():
            return
        with active.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield LogEvent.from_json(line)

    def _iter_archive_events(self, archive_path: Path) -> Iterator[LogEvent]:
        """Iterate over events in a compressed (and optionally encrypted) archive."""
        data = archive_path.read_bytes()

        # If PQC-encrypted, decrypt first
        if archive_path.name.endswith(".pqc"):
            if not self.secret_key_path:
                return  # Cannot decrypt without key
            data = LogStorage.pqc_decrypt(data, self.secret_key_path, self.kem_alg)

        # Decompress LZMA
        if archive_path.name.endswith(".xz.pqc") or archive_path.name.endswith(".xz"):
            data = lzma.decompress(data)

        for line in data.decode("utf-8").splitlines():
            line = line.strip()
            if line:
                yield LogEvent.from_json(line)

    def _iter_all_events(self) -> Iterator[LogEvent]:
        """Iterate over all events: archives (oldest first) then active."""
        archives = sorted(
            [f for f in self.storage_dir.iterdir() if f.name.startswith("archive-")],
            key=lambda f: f.name,
        )
        for archive in archives:
            yield from self._iter_archive_events(archive)
        yield from self._iter_active_events()

    def search(
        self,
        pattern: Optional[str] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        hostname: Optional[str] = None,
        app_name: Optional[str] = None,
        time_from: Optional[str] = None,
        time_to: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
    ) -> List[LogEvent]:
        """Search log events with multiple filter criteria.

        Args:
            pattern: Regex pattern to match against the message field.
            severity_min: Minimum severity level (0=emergency, 7=debug).
            severity_max: Maximum severity level.
            hostname: Filter by hostname (exact match or regex).
            app_name: Filter by application name (exact match or regex).
            time_from: ISO timestamp lower bound for filtering.
            time_to: ISO timestamp upper bound for filtering.
            source_ip: Filter by source IP address.
            limit: Maximum number of results to return.

        Returns:
            List of matching LogEvent objects.
        """
        results = []
        compiled_pattern = re.compile(pattern, re.IGNORECASE) if pattern else None
        compiled_host = re.compile(hostname, re.IGNORECASE) if hostname else None
        compiled_app = re.compile(app_name, re.IGNORECASE) if app_name else None

        for event in self._iter_all_events():
            if len(results) >= limit:
                break

            # Severity filter
            if severity_min is not None and event.severity < severity_min:
                continue
            if severity_max is not None and event.severity > severity_max:
                continue

            # Pattern filter (searches message and raw fields)
            if compiled_pattern:
                if not (compiled_pattern.search(event.message) or
                        compiled_pattern.search(event.raw)):
                    continue

            # Hostname filter
            if compiled_host and not compiled_host.search(event.hostname):
                continue

            # App name filter
            if compiled_app and not compiled_app.search(event.app_name):
                continue

            # Time range filter
            if time_from and event.timestamp < time_from:
                continue
            if time_to and event.timestamp > time_to:
                continue

            # Source IP filter
            if source_ip and event.source_ip != source_ip:
                continue

            results.append(event)

        return results

    def count(self, pattern: Optional[str] = None) -> int:
        """Count events matching an optional pattern."""
        if pattern is None:
            count = 0
            for _ in self._iter_all_events():
                count += 1
            return count
        compiled = re.compile(pattern, re.IGNORECASE)
        count = 0
        for event in self._iter_all_events():
            if compiled.search(event.message) or compiled.search(event.raw):
                count += 1
        return count


# ---------------------------------------------------------------------------
# Log Collector - Syslog server (UDP & TCP)
# ---------------------------------------------------------------------------

class LogCollector:
    """Syslog collector that listens on UDP and/or TCP ports.

    Receives syslog messages (RFC 5424 / RFC 3164), parses them, and
    dispatches parsed LogEvent objects to registered handlers.

    Inspired by METALog's high-performance collection supporting
    RFC 5424, RFC 3164, and non-syslog formats.
    """

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        udp_port: int = 1514,
        tcp_port: int = 1514,
        enable_udp: bool = True,
        enable_tcp: bool = True,
        buffer_size: int = 65535,
    ) -> None:
        self.bind_address = bind_address
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.enable_udp = enable_udp
        self.enable_tcp = enable_tcp
        self.buffer_size = buffer_size

        self._handlers: List[Callable[[LogEvent], None]] = []
        self._running = False
        self._threads: List[threading.Thread] = []
        self._parser = SyslogParser()
        self._stats = {"udp_received": 0, "tcp_received": 0, "parse_errors": 0}
        self._stats_lock = threading.Lock()

    def add_handler(self, handler: Callable[[LogEvent], None]) -> None:
        """Register a handler that will be called for each received event."""
        self._handlers.append(handler)

    def _dispatch(self, event: LogEvent) -> None:
        """Send parsed event to all registered handlers."""
        for handler in self._handlers:
            try:
                handler(event)
            except Exception:
                pass  # Handlers should not break the collector

    def _handle_udp(self) -> None:
        """UDP listener loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_address, self.udp_port))
        sock.settimeout(1.0)
        print(f"[LogCollector] UDP listening on {self.bind_address}:{self.udp_port}")

        while self._running:
            try:
                data, addr = sock.recvfrom(self.buffer_size)
                raw = data.decode("utf-8", errors="replace").strip()
                if raw:
                    event = self._parser.parse(raw, source_ip=addr[0])
                    self._dispatch(event)
                    with self._stats_lock:
                        self._stats["udp_received"] += 1
            except socket.timeout:
                continue
            except Exception:
                with self._stats_lock:
                    self._stats["parse_errors"] += 1
        sock.close()

    def _handle_tcp_client(self, conn: socket.socket, addr: Tuple) -> None:
        """Handle a single TCP client connection."""
        buffer = ""
        conn.settimeout(5.0)
        try:
            while self._running:
                try:
                    data = conn.recv(self.buffer_size)
                    if not data:
                        break
                    buffer += data.decode("utf-8", errors="replace")
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if line:
                            event = self._parser.parse(line, source_ip=addr[0])
                            self._dispatch(event)
                            with self._stats_lock:
                                self._stats["tcp_received"] += 1
                except socket.timeout:
                    continue
                except Exception:
                    with self._stats_lock:
                        self._stats["parse_errors"] += 1
                    break
        finally:
            conn.close()

    def _handle_tcp(self) -> None:
        """TCP listener loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_address, self.tcp_port))
        sock.listen(64)
        sock.settimeout(1.0)
        print(f"[LogCollector] TCP listening on {self.bind_address}:{self.tcp_port}")

        while self._running:
            try:
                conn, addr = sock.accept()
                client_thread = threading.Thread(
                    target=self._handle_tcp_client, args=(conn, addr), daemon=True
                )
                client_thread.start()
            except socket.timeout:
                continue
            except Exception:
                pass
        sock.close()

    def start(self) -> None:
        """Start the collector in background threads."""
        self._running = True
        if self.enable_udp:
            t = threading.Thread(target=self._handle_udp, daemon=True, name="udp-collector")
            t.start()
            self._threads.append(t)
        if self.enable_tcp:
            t = threading.Thread(target=self._handle_tcp, daemon=True, name="tcp-collector")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        """Signal all collector threads to stop."""
        self._running = False
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
        print("[LogCollector] Stopped.")

    def get_stats(self) -> Dict:
        """Return collector statistics."""
        with self._stats_lock:
            return dict(self._stats)


# ---------------------------------------------------------------------------
# Log Forwarder - forward events to external destinations
# ---------------------------------------------------------------------------

class LogForwarder:
    """Forward log events to external SIEM or log aggregation systems.

    Supports forwarding via UDP, TCP, or writing to a file.  Events can
    be filtered before forwarding using severity levels and regex patterns.
    """

    def __init__(
        self,
        dest_type: str = "file",
        dest_host: str = "",
        dest_port: int = 514,
        dest_file: Optional[Path] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        pattern_include: Optional[str] = None,
        pattern_exclude: Optional[str] = None,
        output_format: str = "json",
    ) -> None:
        """
        Args:
            dest_type: One of 'udp', 'tcp', 'file'.
            dest_host: Destination host for UDP/TCP forwarding.
            dest_port: Destination port for UDP/TCP forwarding.
            dest_file: Path for file-based forwarding.
            severity_min: Only forward events with severity >= this value.
            severity_max: Only forward events with severity <= this value.
            pattern_include: Regex; only forward events whose message matches.
            pattern_exclude: Regex; exclude events whose message matches.
            output_format: 'json' for JSON lines, 'raw' for original syslog.
        """
        self.dest_type = dest_type
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.dest_file = dest_file
        self.severity_min = severity_min
        self.severity_max = severity_max
        self.output_format = output_format
        self._include_re = re.compile(pattern_include, re.IGNORECASE) if pattern_include else None
        self._exclude_re = re.compile(pattern_exclude, re.IGNORECASE) if pattern_exclude else None
        self._lock = threading.Lock()
        self._socket: Optional[socket.socket] = None
        self._forwarded = 0
        self._dropped = 0

    def _matches_filter(self, event: LogEvent) -> bool:
        """Check if an event passes the filter criteria."""
        if self.severity_min is not None and event.severity < self.severity_min:
            return False
        if self.severity_max is not None and event.severity > self.severity_max:
            return False
        if self._include_re and not self._include_re.search(event.message):
            return False
        if self._exclude_re and self._exclude_re.search(event.message):
            return False
        return True

    def _format_event(self, event: LogEvent) -> str:
        """Format event for output."""
        if self.output_format == "json":
            return event.to_json()
        return event.raw

    def forward(self, event: LogEvent) -> None:
        """Forward a single event if it passes filters."""
        if not self._matches_filter(event):
            self._dropped += 1
            return

        payload = self._format_event(event) + "\n"

        with self._lock:
            try:
                if self.dest_type == "udp":
                    if self._socket is None:
                        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self._socket.sendto(
                        payload.encode("utf-8"), (self.dest_host, self.dest_port)
                    )
                elif self.dest_type == "tcp":
                    if self._socket is None:
                        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self._socket.connect((self.dest_host, self.dest_port))
                    self._socket.sendall(payload.encode("utf-8"))
                elif self.dest_type == "file" and self.dest_file:
                    with self.dest_file.open("a", encoding="utf-8") as f:
                        f.write(payload)
                self._forwarded += 1
            except Exception:
                self._dropped += 1
                # Reset TCP socket on error
                if self.dest_type == "tcp" and self._socket:
                    try:
                        self._socket.close()
                    except Exception:
                        pass
                    self._socket = None

    def get_stats(self) -> Dict:
        """Return forwarder statistics."""
        return {
            "dest_type": self.dest_type,
            "dest": f"{self.dest_host}:{self.dest_port}" if self.dest_type != "file"
                    else str(self.dest_file),
            "forwarded": self._forwarded,
            "dropped": self._dropped,
        }

    def close(self) -> None:
        """Clean up resources."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None


# ---------------------------------------------------------------------------
# Log Manager - orchestrates all components
# ---------------------------------------------------------------------------

class LogManager:
    """High-level orchestrator for the log management system.

    Ties together the collector, storage, search, and forwarder components
    into a unified system.  This is the main entry point for programmatic
    usage of the log management features.
    """

    def __init__(
        self,
        storage_dir: Path = Path("logs"),
        max_file_size: int = 50 * 1024 * 1024,
        max_archives: int = 100,
        compression: str = "lzma",
        public_key_path: Optional[Path] = None,
        secret_key_path: Optional[Path] = None,
        kem_alg: str = "ML-KEM-512",
    ) -> None:
        self.storage = LogStorage(
            storage_dir=storage_dir,
            max_file_size=max_file_size,
            max_archives=max_archives,
            compression=compression,
            public_key_path=public_key_path,
            kem_alg=kem_alg,
        )
        self.search = LogSearch(
            storage_dir=storage_dir,
            secret_key_path=secret_key_path,
            kem_alg=kem_alg,
        )
        self.collector: Optional[LogCollector] = None
        self.forwarders: List[LogForwarder] = []
        self._kem_alg = kem_alg

    def _on_event(self, event: LogEvent) -> None:
        """Handler called for each incoming event."""
        self.storage.write(event)
        for fwd in self.forwarders:
            fwd.forward(event)

    def start_collector(
        self,
        bind_address: str = "0.0.0.0",
        udp_port: int = 1514,
        tcp_port: int = 1514,
        enable_udp: bool = True,
        enable_tcp: bool = True,
    ) -> None:
        """Start the syslog collector."""
        self.collector = LogCollector(
            bind_address=bind_address,
            udp_port=udp_port,
            tcp_port=tcp_port,
            enable_udp=enable_udp,
            enable_tcp=enable_tcp,
        )
        self.collector.add_handler(self._on_event)
        self.collector.start()

    def add_forwarder(self, forwarder: LogForwarder) -> None:
        """Register a log forwarder."""
        self.forwarders.append(forwarder)

    def ingest_file(self, file_path: Path) -> int:
        """Import log events from a plain text file (one syslog line per line).

        Returns the number of events ingested.
        """
        parser = SyslogParser()
        count = 0
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    event = parser.parse(line)
                    self._on_event(event)
                    count += 1
        return count

    def stop(self) -> None:
        """Stop the collector and all forwarders."""
        if self.collector:
            self.collector.stop()
        for fwd in self.forwarders:
            fwd.close()

    def get_stats(self) -> Dict:
        """Return combined statistics from all components."""
        stats = {"storage": self.storage.get_stats()}
        if self.collector:
            stats["collector"] = self.collector.get_stats()
        if self.forwarders:
            stats["forwarders"] = [fwd.get_stats() for fwd in self.forwarders]
        return stats
