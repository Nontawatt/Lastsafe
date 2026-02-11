#!/usr/bin/env python3
"""
lastsafe: PQC‑enhanced file transfer tool based on rclone
========================================================

This script provides a simple command line interface to encrypt and
decrypt files using a post‑quantum key encapsulation mechanism (KEM) and
symmetric encryption before synchronising data via rclone.  The tool
uses the ML‑KEM algorithm from the CRYSTALS Kyber family (standardised
as FIPS 203) for key encapsulation and AES‑GCM for symmetric
encryption.  See the accompanying ``README.md`` for installation and
usage details.

Features
--------
* Generate a PQC keypair (public and private keys) for ML‑KEM.
* Encrypt individual files or entire directories.  Encrypted files
  contain the KEM ciphertext and AES nonce in a small header so that
  decryption can recover the symmetric key.
* Decrypt previously encrypted files using the stored secret key.
* Wrap rclone commands to upload encrypted data to a remote or download
  and decrypt data from a remote.

This script is intended as a demonstration of integrating post‑quantum
cryptography with existing tools such as rclone.  It is not a full
replacement for rclone’s own ``crypt`` backend.  Always review the
security implications and keep your private keys safe.
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Tuple

try:
    import oqs  # type: ignore
except ImportError as exc:
    sys.exit(
        "The 'oqs' module is required. Please install liboqs-python via 'pip install liboqs-python'."
    )

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except ImportError as exc:
    sys.exit(
        "The 'cryptography' module is required. Please install it via 'pip install cryptography'."
    )

import secrets


DEFAULT_KEM_ALG = "ML-KEM-512"


def generate_keys(output_dir: Path, kem_alg: str = DEFAULT_KEM_ALG) -> None:
    """Generate a PQC keypair and store it in ``output_dir``.

    The public key is saved as ``public.key`` and the secret key as
    ``private.key``.  Any existing files with those names will be
    overwritten.

    Args:
        output_dir: Directory where key files will be saved.
        kem_alg: Name of the KEM algorithm supported by liboqs.  The
            default is ML‑KEM‑512, which is based on the Kyber KEM
            standardised by NIST【901244997312077†L420-L433】.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    # Generate keypair using liboqs
    with oqs.KeyEncapsulation(kem_alg) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    # Save keys to files
    (output_dir / "public.key").write_bytes(public_key)
    (output_dir / "private.key").write_bytes(secret_key)
    print(f"Generated {kem_alg} keypair in {output_dir}")


def _derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 256‑bit AES key from the shared secret.

    The shared secret returned by ``encap_secret`` or ``decap_secret`` may
    be longer than needed.  We simply take the first 32 bytes for
    AES‑256.  In practice you should use a proper KDF; this is for
    demonstration purposes only.
    """
    if len(shared_secret) < 32:
        raise ValueError("Shared secret is too short to derive AES‑256 key")
    return shared_secret[:32]


def encrypt_file(
    in_path: Path, out_path: Path, public_key: bytes, kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Encrypt a single file using PQC KEM and AES‑GCM.

    The resulting file format is:

    * ``uint32``: length of the KEM ciphertext (big endian)
    * KEM ciphertext
    * 12‑byte AES nonce
    * AES‑GCM encrypted payload (includes authentication tag)

    Args:
        in_path: Path to the plaintext file to encrypt.
        out_path: Path where the encrypted file will be written.
        public_key: Public key bytes for the recipient.
        kem_alg: Name of the KEM algorithm to use.
    """
    data = in_path.read_bytes()
    with oqs.KeyEncapsulation(kem_alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    aes_key = _derive_aes_key(shared_secret)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    # Write to file: header length, ciphertext, nonce, encrypted_data
    with out_path.open("wb") as f:
        f.write(struct.pack("!I", len(ciphertext)))
        f.write(ciphertext)
        f.write(nonce)
        f.write(encrypted_data)


def decrypt_file(
    in_path: Path, out_path: Path, secret_key: bytes, kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Decrypt a single file produced by ``encrypt_file``.

    Args:
        in_path: Path to the encrypted file.
        out_path: Path where the decrypted plaintext will be written.
        secret_key: Secret key bytes corresponding to the public key used
            to encrypt the file.
        kem_alg: Name of the KEM algorithm used when encrypting.
    """
    with in_path.open("rb") as f:
        header = f.read(4)
        if len(header) != 4:
            raise ValueError("Encrypted file too short to read header")
        (ct_len,) = struct.unpack("!I", header)
        ciphertext = f.read(ct_len)
        nonce = f.read(12)
        encrypted_data = f.read()
    with oqs.KeyEncapsulation(kem_alg, secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    aes_key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(aes_key)
    decrypted = aesgcm.decrypt(nonce, encrypted_data, None)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(decrypted)


def encrypt_directory(src_dir: Path, dst_dir: Path, public_key: bytes, kem_alg: str) -> None:
    """Encrypt all files in ``src_dir`` recursively into ``dst_dir``.

    Directory structure is preserved.  Only regular files are encrypted; other
    file types are ignored.
    """
    for root, dirs, files in os.walk(src_dir):
        for filename in files:
            plain_path = Path(root) / filename
            # Determine relative path
            relative = plain_path.relative_to(src_dir)
            enc_path = dst_dir / relative
            enc_path.parent.mkdir(parents=True, exist_ok=True)
            encrypt_file(plain_path, enc_path, public_key, kem_alg)


def decrypt_directory(src_dir: Path, dst_dir: Path, secret_key: bytes, kem_alg: str) -> None:
    """Decrypt all files in ``src_dir`` recursively into ``dst_dir``.

    Directory structure is preserved.  Only regular files are decrypted; other
    file types are ignored.
    """
    for root, dirs, files in os.walk(src_dir):
        for filename in files:
            enc_path = Path(root) / filename
            relative = enc_path.relative_to(src_dir)
            plain_path = dst_dir / relative
            decrypt_file(enc_path, plain_path, secret_key, kem_alg)


def run_rclone(args: list) -> int:
    """Execute rclone with the given arguments.

    This helper function invokes the ``rclone`` binary and returns its
    exit code.  If rclone is not installed, an informative error is
    printed and a non‑zero status is returned.
    """
    try:
        proc = subprocess.run(["rclone"] + args, check=False)
        return proc.returncode
    except FileNotFoundError:
        print(
            "Error: rclone is not installed or not found in PATH. Please install rclone as described in the README."
        )
        return 1


def encrypt_and_upload(
    src: Path, remote_dest: str, key_dir: Path, kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Encrypt a directory and upload it to a remote using rclone.

    This function creates a temporary directory inside the system's
    temporary folder, encrypts the files under ``src`` using the public
    key from ``key_dir``, then runs ``rclone copy`` to ``remote_dest``.

    Args:
        src: Local directory to encrypt.
        remote_dest: Remote path recognised by rclone (e.g. ``remote:backup``).
        key_dir: Directory containing ``public.key``.
        kem_alg: Name of the KEM algorithm.
    """
    public_key_path = key_dir / "public.key"
    if not public_key_path.exists():
        raise FileNotFoundError(f"Public key not found at {public_key_path}")
    public_key = public_key_path.read_bytes()
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        encrypt_directory(src, tmp_path, public_key, kem_alg)
        # Use rclone to copy the encrypted directory to the remote
        exit_code = run_rclone(["copy", str(tmp_path), remote_dest, "--progress"])
        if exit_code != 0:
            raise RuntimeError(f"rclone exited with status {exit_code}")
        print(f"Encrypted data uploaded to {remote_dest}")


def download_and_decrypt(
    remote_src: str, dest: Path, key_dir: Path, kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Download encrypted data from a remote using rclone and decrypt it.

    This function creates a temporary directory, uses ``rclone copy`` to
    fetch the encrypted files from ``remote_src`` into the temporary
    directory, then decrypts them into ``dest`` using the secret key from
    ``key_dir``.

    Args:
        remote_src: Remote path recognised by rclone (e.g. ``remote:backup``).
        dest: Local directory where decrypted data will be written.
        key_dir: Directory containing ``private.key``.
        kem_alg: Name of the KEM algorithm.
    """
    secret_key_path = key_dir / "private.key"
    if not secret_key_path.exists():
        raise FileNotFoundError(f"Private key not found at {secret_key_path}")
    secret_key = secret_key_path.read_bytes()
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        exit_code = run_rclone(["copy", remote_src, str(tmp_path), "--progress"])
        if exit_code != 0:
            raise RuntimeError(f"rclone exited with status {exit_code}")
        decrypt_directory(tmp_path, dest, secret_key, kem_alg)
        print(f"Data downloaded from {remote_src} and decrypted into {dest}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-keys command
    parser_keys = subparsers.add_parser(
        "generate-keys", help="Generate a PQC keypair (public.key and private.key)"
    )
    parser_keys.add_argument(
        "--out", type=Path, default=Path("keys"), help="Directory to write keys (default: ./keys)"
    )
    parser_keys.add_argument(
        "--alg",
        type=str,
        default=DEFAULT_KEM_ALG,
        help=f"KEM algorithm to use (default: {DEFAULT_KEM_ALG})",
    )

    # encrypt command
    parser_enc = subparsers.add_parser("encrypt", help="Encrypt a file or directory")
    parser_enc.add_argument("src", type=Path, help="File or directory to encrypt")
    parser_enc.add_argument("dst", type=Path, help="Destination path for encrypted output")
    parser_enc.add_argument(
        "--key-dir", type=Path, default=Path("keys"), help="Directory containing public.key"
    )
    parser_enc.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )

    # decrypt command
    parser_dec = subparsers.add_parser("decrypt", help="Decrypt a file or directory")
    parser_dec.add_argument("src", type=Path, help="Encrypted file or directory to decrypt")
    parser_dec.add_argument("dst", type=Path, help="Destination path for decrypted output")
    parser_dec.add_argument(
        "--key-dir", type=Path, default=Path("keys"), help="Directory containing private.key"
    )
    parser_dec.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )

    # upload command
    parser_up = subparsers.add_parser(
        "encrypt-upload", help="Encrypt a directory and upload via rclone"
    )
    parser_up.add_argument("src", type=Path, help="Local directory to encrypt and upload")
    parser_up.add_argument("remote", type=str, help="Remote destination (e.g. remote:backup)")
    parser_up.add_argument(
        "--key-dir", type=Path, default=Path("keys"), help="Directory containing public.key"
    )
    parser_up.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )

    # download command
    parser_down = subparsers.add_parser(
        "download-decrypt", help="Download via rclone and decrypt files"
    )
    parser_down.add_argument("remote", type=str, help="Remote source (e.g. remote:backup)")
    parser_down.add_argument(
        "dst", type=Path, help="Destination directory for decrypted data"
    )
    parser_down.add_argument(
        "--key-dir", type=Path, default=Path("keys"), help="Directory containing private.key"
    )
    parser_down.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )

    # -----------------------------------------------------------------------
    # Log Management commands (inspired by SRAN METALog)
    # -----------------------------------------------------------------------

    # log-collect: start syslog collector
    parser_logcol = subparsers.add_parser(
        "log-collect",
        help="Start syslog collector (UDP/TCP, RFC 5424 & RFC 3164)",
    )
    parser_logcol.add_argument(
        "--bind", type=str, default="0.0.0.0", help="Bind address (default: 0.0.0.0)"
    )
    parser_logcol.add_argument(
        "--udp-port", type=int, default=1514, help="UDP port (default: 1514)"
    )
    parser_logcol.add_argument(
        "--tcp-port", type=int, default=1514, help="TCP port (default: 1514)"
    )
    parser_logcol.add_argument(
        "--no-udp", action="store_true", help="Disable UDP listener"
    )
    parser_logcol.add_argument(
        "--no-tcp", action="store_true", help="Disable TCP listener"
    )
    parser_logcol.add_argument(
        "--log-dir", type=Path, default=Path("logs"), help="Log storage directory (default: ./logs)"
    )
    parser_logcol.add_argument(
        "--max-file-size", type=int, default=50, help="Max log file size in MB before rotation (default: 50)"
    )
    parser_logcol.add_argument(
        "--max-archives", type=int, default=100, help="Max number of archived log files (default: 100)"
    )
    parser_logcol.add_argument(
        "--key-dir", type=Path, default=None,
        help="Key directory for PQC encryption of archived logs (optional)"
    )
    parser_logcol.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )
    parser_logcol.add_argument(
        "--forward-udp", type=str, default=None,
        help="Forward events via UDP to host:port (e.g. siem.example.com:514)"
    )
    parser_logcol.add_argument(
        "--forward-tcp", type=str, default=None,
        help="Forward events via TCP to host:port (e.g. siem.example.com:514)"
    )
    parser_logcol.add_argument(
        "--forward-file", type=Path, default=None,
        help="Forward events to a file"
    )

    # log-ingest: import logs from a file
    parser_logingest = subparsers.add_parser(
        "log-ingest",
        help="Import log events from a text file into storage",
    )
    parser_logingest.add_argument(
        "file", type=Path, help="Log file to import (one syslog line per line)"
    )
    parser_logingest.add_argument(
        "--log-dir", type=Path, default=Path("logs"), help="Log storage directory (default: ./logs)"
    )
    parser_logingest.add_argument(
        "--key-dir", type=Path, default=None,
        help="Key directory for PQC encryption of archived logs (optional)"
    )
    parser_logingest.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )

    # log-search: search stored logs
    parser_logsearch = subparsers.add_parser(
        "log-search",
        help="Search log events with filters (pattern, severity, time range)",
    )
    parser_logsearch.add_argument(
        "--pattern", "-p", type=str, default=None, help="Regex pattern to search in messages"
    )
    parser_logsearch.add_argument(
        "--severity", "-s", type=str, default=None,
        help="Severity filter: name (e.g. ERROR) or range (e.g. 0-3)"
    )
    parser_logsearch.add_argument(
        "--hostname", type=str, default=None, help="Filter by hostname (regex)"
    )
    parser_logsearch.add_argument(
        "--app", type=str, default=None, help="Filter by app name (regex)"
    )
    parser_logsearch.add_argument(
        "--from", dest="time_from", type=str, default=None, help="Time range start (ISO format)"
    )
    parser_logsearch.add_argument(
        "--to", dest="time_to", type=str, default=None, help="Time range end (ISO format)"
    )
    parser_logsearch.add_argument(
        "--source-ip", type=str, default=None, help="Filter by source IP"
    )
    parser_logsearch.add_argument(
        "--limit", "-n", type=int, default=50, help="Max results (default: 50)"
    )
    parser_logsearch.add_argument(
        "--log-dir", type=Path, default=Path("logs"), help="Log storage directory (default: ./logs)"
    )
    parser_logsearch.add_argument(
        "--key-dir", type=Path, default=None,
        help="Key directory for decrypting PQC-encrypted archives (optional)"
    )
    parser_logsearch.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )
    parser_logsearch.add_argument(
        "--json", dest="output_json", action="store_true", help="Output results as JSON"
    )

    # log-stats: show storage and collector stats
    parser_logstats = subparsers.add_parser(
        "log-stats",
        help="Show log storage statistics",
    )
    parser_logstats.add_argument(
        "--log-dir", type=Path, default=Path("logs"), help="Log storage directory (default: ./logs)"
    )

    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_keys(args.out, args.alg)
    elif args.command == "encrypt":
        # Determine whether src is file or directory
        if args.src.is_file():
            pub_key = (args.key_dir / "public.key").read_bytes()
            encrypt_file(args.src, args.dst, pub_key, args.alg)
            print(f"Encrypted {args.src} -> {args.dst}")
        else:
            pub_key = (args.key_dir / "public.key").read_bytes()
            encrypt_directory(args.src, args.dst, pub_key, args.alg)
            print(f"Encrypted directory {args.src} -> {args.dst}")
    elif args.command == "decrypt":
        if args.src.is_file():
            sec_key = (args.key_dir / "private.key").read_bytes()
            decrypt_file(args.src, args.dst, sec_key, args.alg)
            print(f"Decrypted {args.src} -> {args.dst}")
        else:
            sec_key = (args.key_dir / "private.key").read_bytes()
            decrypt_directory(args.src, args.dst, sec_key, args.alg)
            print(f"Decrypted directory {args.src} -> {args.dst}")
    elif args.command == "encrypt-upload":
        encrypt_and_upload(args.src, args.remote, args.key_dir, args.alg)
    elif args.command == "download-decrypt":
        download_and_decrypt(args.remote, args.dst, args.key_dir, args.alg)

    # ------------------------------------------------------------------
    # Log Management command handlers
    # ------------------------------------------------------------------
    elif args.command == "log-collect":
        from log_manager import LogForwarder, LogManager

        pub_key_path = (args.key_dir / "public.key") if args.key_dir else None
        manager = LogManager(
            storage_dir=args.log_dir,
            max_file_size=args.max_file_size * 1024 * 1024,
            max_archives=args.max_archives,
            public_key_path=pub_key_path,
            kem_alg=args.alg,
        )

        # Set up forwarders if requested
        if args.forward_udp:
            host, port = args.forward_udp.rsplit(":", 1)
            manager.add_forwarder(LogForwarder(
                dest_type="udp", dest_host=host, dest_port=int(port)
            ))
        if args.forward_tcp:
            host, port = args.forward_tcp.rsplit(":", 1)
            manager.add_forwarder(LogForwarder(
                dest_type="tcp", dest_host=host, dest_port=int(port)
            ))
        if args.forward_file:
            manager.add_forwarder(LogForwarder(
                dest_type="file", dest_file=args.forward_file
            ))

        manager.start_collector(
            bind_address=args.bind,
            udp_port=args.udp_port,
            tcp_port=args.tcp_port,
            enable_udp=not args.no_udp,
            enable_tcp=not args.no_tcp,
        )
        pqc_status = "enabled" if pub_key_path else "disabled"
        print(f"Log collector running (PQC encryption: {pqc_status})")
        print("Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(10)
                stats = manager.get_stats()
                collector_stats = stats.get("collector", {})
                total = collector_stats.get("udp_received", 0) + collector_stats.get("tcp_received", 0)
                print(f"  Events received: {total} | Storage: {stats['storage']['active_log_events']} active events, "
                      f"{stats['storage']['archive_count']} archives")
        except KeyboardInterrupt:
            print("\nShutting down collector...")
            manager.stop()

    elif args.command == "log-ingest":
        from log_manager import LogManager

        pub_key_path = (args.key_dir / "public.key") if args.key_dir else None
        manager = LogManager(
            storage_dir=args.log_dir,
            public_key_path=pub_key_path,
            kem_alg=args.alg,
        )
        count = manager.ingest_file(args.file)
        print(f"Ingested {count} log events from {args.file}")

    elif args.command == "log-search":
        from log_manager import LogSearch, SyslogSeverity

        sec_key_path = (args.key_dir / "private.key") if args.key_dir else None
        searcher = LogSearch(
            storage_dir=args.log_dir,
            secret_key_path=sec_key_path,
            kem_alg=args.alg,
        )

        # Parse severity filter
        severity_min = None
        severity_max = None
        if args.severity:
            sev = args.severity.upper()
            if "-" in sev:
                parts = sev.split("-", 1)
                severity_min = int(parts[0]) if parts[0].isdigit() else SyslogSeverity[parts[0]].value
                severity_max = int(parts[1]) if parts[1].isdigit() else SyslogSeverity[parts[1]].value
            elif sev.isdigit():
                severity_max = int(sev)
            else:
                severity_max = SyslogSeverity[sev].value

        results = searcher.search(
            pattern=args.pattern,
            severity_min=severity_min,
            severity_max=severity_max,
            hostname=args.hostname,
            app_name=args.app,
            time_from=args.time_from,
            time_to=args.time_to,
            source_ip=args.source_ip,
            limit=args.limit,
        )

        if args.output_json:
            for event in results:
                print(event.to_json())
        else:
            for event in results:
                sev = event.severity_name
                print(f"[{event.timestamp}] [{sev:13s}] {event.hostname} {event.app_name}: {event.message}")

        print(f"\n--- {len(results)} event(s) found ---")

    elif args.command == "log-stats":
        from log_manager import LogStorage

        storage = LogStorage(storage_dir=args.log_dir)
        stats = storage.get_stats()
        print("Log Storage Statistics")
        print("=" * 50)
        for key, value in stats.items():
            label = key.replace("_", " ").title()
            if "bytes" in key.lower() and isinstance(value, (int, float)):
                if value > 1024 * 1024:
                    value = f"{value:,} ({value / 1024 / 1024:.1f} MB)"
                elif value > 1024:
                    value = f"{value:,} ({value / 1024:.1f} KB)"
                else:
                    value = f"{value:,} B"
            print(f"  {label}: {value}")

    else:
        parser.error("Unknown command")


if __name__ == "__main__":
    main()