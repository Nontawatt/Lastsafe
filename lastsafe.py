#!/usr/bin/env python3
"""
lastsafe: PQC-enhanced file transfer tool
==========================================

This script provides a simple command line interface to encrypt and
decrypt files using a post-quantum key encapsulation mechanism (KEM) and
symmetric encryption.  The tool uses the ML-KEM algorithm from the
CRYSTALS Kyber family (standardised as FIPS 203) for key encapsulation
and AES-GCM for symmetric encryption.

Features
--------
* Generate a PQC keypair (public and private keys) for ML-KEM.
* Encrypt individual files or entire directories.
* Decrypt previously encrypted files using the stored secret key.
* Direct peer-to-peer file transfer over TCP sockets with PQC encryption.
* Optional rclone integration for cloud storage.

This script demonstrates integrating post-quantum cryptography with
file transfer. Always review the security implications and keep your
private keys safe.
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Tuple, Optional

try:
    import oqs
except ImportError:
    sys.exit(
        "The 'oqs' module is required. Please install liboqs-python via 'pip install liboqs-python'."
    )

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit(
        "The 'cryptography' module is required. Please install it via 'pip install cryptography'."
    )

import secrets


DEFAULT_KEM_ALG = "ML-KEM-512"
DEFAULT_PORT = 5555
BUFFER_SIZE = 8192


def generate_keys(output_dir: Path, kem_alg: str = DEFAULT_KEM_ALG) -> None:
    """Generate a PQC keypair and store it in output_dir.

    The public key is saved as public.key and the secret key as
    private.key. Any existing files with those names will be
    overwritten.

    Args:
        output_dir: Directory where key files will be saved.
        kem_alg: Name of the KEM algorithm supported by liboqs.
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
    print(f"  Public key:  {output_dir}/public.key")
    print(f"  Private key: {output_dir}/private.key")
    print("\nWARNING: Keep your private key secure!")


def _derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 256-bit AES key from the shared secret.

    The shared secret returned by encap_secret or decap_secret may
    be longer than needed. We simply take the first 32 bytes for
    AES-256.
    """
    if len(shared_secret) < 32:
        raise ValueError("Shared secret is too short to derive AES-256 key")
    return shared_secret[:32]


def encrypt_file(
    in_path: Path, out_path: Path, public_key: bytes, kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Encrypt a single file using PQC KEM and AES-GCM.

    The resulting file format is:
    * uint32: length of the KEM ciphertext (big endian)
    * KEM ciphertext
    * 12-byte AES nonce
    * AES-GCM encrypted payload (includes authentication tag)

    Args:
        in_path: Path to the plaintext file to encrypt.
        out_path: Path where the encrypted file will be written.
        public_key: Public key bytes for the recipient.
        kem_alg: Name of the KEM algorithm to use.
    """
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")

    data = in_path.read_bytes()
    with oqs.KeyEncapsulation(kem_alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    aes_key = _derive_aes_key(shared_secret)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    encrypted_data = aesgcm.encrypt(nonce, data, None)

    # Write to file: header length, ciphertext, nonce, encrypted_data
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        f.write(struct.pack("!I", len(ciphertext)))
        f.write(ciphertext)
        f.write(nonce)
        f.write(encrypted_data)


def decrypt_file(
    in_path: Path, out_path: Path, secret_key: bytes, kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Decrypt a single file produced by encrypt_file.

    Args:
        in_path: Path to the encrypted file.
        out_path: Path where the decrypted plaintext will be written.
        secret_key: Secret key bytes corresponding to the public key used
            to encrypt the file.
        kem_alg: Name of the KEM algorithm used when encrypting.
    """
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")

    with in_path.open("rb") as f:
        header = f.read(4)
        if len(header) != 4:
            raise ValueError("Encrypted file too short to read header")
        (ct_len,) = struct.unpack("!I", header)
        ciphertext = f.read(ct_len)
        if len(ciphertext) != ct_len:
            raise ValueError(f"Expected {ct_len} bytes of ciphertext, got {len(ciphertext)}")
        nonce = f.read(12)
        if len(nonce) != 12:
            raise ValueError("Failed to read nonce")
        encrypted_data = f.read()

    with oqs.KeyEncapsulation(kem_alg, secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    aes_key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(aes_key)
    decrypted = aesgcm.decrypt(nonce, encrypted_data, None)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(decrypted)


def encrypt_directory(src_dir: Path, dst_dir: Path, public_key: bytes, kem_alg: str) -> None:
    """Encrypt all files in src_dir recursively into dst_dir.

    Directory structure is preserved. Only regular files are encrypted; other
    file types are ignored.
    """
    if not src_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {src_dir}")

    file_count = 0
    for root, dirs, files in os.walk(src_dir):
        for filename in files:
            plain_path = Path(root) / filename
            # Determine relative path
            relative = plain_path.relative_to(src_dir)
            enc_path = dst_dir / relative
            enc_path.parent.mkdir(parents=True, exist_ok=True)
            print(f"Encrypting: {relative}")
            encrypt_file(plain_path, enc_path, public_key, kem_alg)
            file_count += 1
    print(f"\nEncrypted {file_count} files from {src_dir} to {dst_dir}")


def decrypt_directory(src_dir: Path, dst_dir: Path, secret_key: bytes, kem_alg: str) -> None:
    """Decrypt all files in src_dir recursively into dst_dir.

    Directory structure is preserved. Only regular files are decrypted; other
    file types are ignored.
    """
    if not src_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {src_dir}")

    file_count = 0
    for root, dirs, files in os.walk(src_dir):
        for filename in files:
            enc_path = Path(root) / filename
            relative = enc_path.relative_to(src_dir)
            plain_path = dst_dir / relative
            print(f"Decrypting: {relative}")
            decrypt_file(enc_path, plain_path, secret_key, kem_alg)
            file_count += 1
    print(f"\nDecrypted {file_count} files from {src_dir} to {dst_dir}")


def run_rclone(args: list) -> int:
    """Execute rclone with the given arguments.

    This helper function invokes the rclone binary and returns its
    exit code. If rclone is not installed, an informative error is
    printed and a non-zero status is returned.
    """
    try:
        proc = subprocess.run(["rclone"] + args, check=False)
        return proc.returncode
    except FileNotFoundError:
        print(
            "Error: rclone is not installed or not found in PATH. "
            "Please install rclone or use the 'send' and 'receive' commands for direct transfer."
        )
        return 1


def encrypt_and_upload(
    src: Path, remote_dest: str, key_dir: Path, kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Encrypt a directory and upload it to a remote using rclone.

    This function creates a temporary directory inside the system's
    temporary folder, encrypts the files under src using the public
    key from key_dir, then runs rclone copy to remote_dest.

    Args:
        src: Local directory to encrypt.
        remote_dest: Remote path recognised by rclone (e.g. remote:backup).
        key_dir: Directory containing public.key.
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
        print(f"\nUploading to {remote_dest}...")
        exit_code = run_rclone(["copy", str(tmp_path), remote_dest, "--progress"])
        if exit_code != 0:
            raise RuntimeError(f"rclone exited with status {exit_code}")
        print(f"Encrypted data uploaded to {remote_dest}")


def download_and_decrypt(
    remote_src: str, dest: Path, key_dir: Path, kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Download encrypted data from a remote using rclone and decrypt it.

    This function creates a temporary directory, uses rclone copy to
    fetch the encrypted files from remote_src into the temporary
    directory, then decrypts them into dest using the secret key from
    key_dir.

    Args:
        remote_src: Remote path recognised by rclone (e.g. remote:backup).
        dest: Local directory where decrypted data will be written.
        key_dir: Directory containing private.key.
        kem_alg: Name of the KEM algorithm.
    """
    secret_key_path = key_dir / "private.key"
    if not secret_key_path.exists():
        raise FileNotFoundError(f"Private key not found at {secret_key_path}")
    secret_key = secret_key_path.read_bytes()
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        print(f"Downloading from {remote_src}...")
        exit_code = run_rclone(["copy", remote_src, str(tmp_path), "--progress"])
        if exit_code != 0:
            raise RuntimeError(f"rclone exited with status {exit_code}")
        decrypt_directory(tmp_path, dest, secret_key, kem_alg)
        print(f"Data downloaded from {remote_src} and decrypted into {dest}")


# ============================================================================
# DIRECT FILE TRANSFER (Peer-to-Peer)
# ============================================================================

def send_file_direct(
    file_path: Path,
    host: str,
    port: int,
    recipient_public_key: bytes,
    kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Send an encrypted file directly to a receiver via TCP socket.

    Args:
        file_path: Path to the file to send.
        host: IP address or hostname of the receiver.
        port: Port number to connect to.
        recipient_public_key: Public key of the recipient.
        kem_alg: KEM algorithm to use.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    print(f"Encrypting {file_path.name}...")

    # Read and encrypt file
    data = file_path.read_bytes()
    with oqs.KeyEncapsulation(kem_alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(recipient_public_key)
    aes_key = _derive_aes_key(shared_secret)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    encrypted_data = aesgcm.encrypt(nonce, data, None)

    # Prepare metadata
    metadata = {
        "filename": file_path.name,
        "kem_alg": kem_alg,
        "ct_len": len(ciphertext),
    }
    metadata_bytes = json.dumps(metadata).encode('utf-8')

    # Connect to receiver
    print(f"Connecting to {host}:{port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        print("Connected!")

        # Send metadata length (4 bytes) + metadata
        sock.sendall(struct.pack("!I", len(metadata_bytes)))
        sock.sendall(metadata_bytes)

        # Send KEM ciphertext
        sock.sendall(ciphertext)

        # Send AES nonce
        sock.sendall(nonce)

        # Send encrypted data with progress
        total_sent = 0
        data_len = len(encrypted_data)
        print(f"Sending encrypted file ({data_len} bytes)...")

        while total_sent < data_len:
            chunk = encrypted_data[total_sent:total_sent + BUFFER_SIZE]
            sock.sendall(chunk)
            total_sent += len(chunk)
            progress = (total_sent / data_len) * 100
            print(f"\rProgress: {progress:.1f}%", end='', flush=True)

        print("\nFile sent successfully!")


def receive_file_direct(
    port: int,
    output_dir: Path,
    secret_key: bytes,
    kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Receive an encrypted file via TCP socket and decrypt it.

    Args:
        port: Port number to listen on.
        output_dir: Directory where the decrypted file will be saved.
        secret_key: Secret key for decryption.
        kem_alg: KEM algorithm to use.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('0.0.0.0', port))
        server_sock.listen(1)

        print(f"Listening on port {port}...")
        print("Waiting for incoming file transfer...")

        conn, addr = server_sock.accept()
        with conn:
            print(f"Connection from {addr[0]}:{addr[1]}")

            # Receive metadata
            meta_len_bytes = conn.recv(4)
            if len(meta_len_bytes) != 4:
                raise ValueError("Failed to receive metadata length")
            meta_len = struct.unpack("!I", meta_len_bytes)[0]

            metadata_bytes = b''
            while len(metadata_bytes) < meta_len:
                chunk = conn.recv(min(BUFFER_SIZE, meta_len - len(metadata_bytes)))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving metadata")
                metadata_bytes += chunk

            metadata = json.loads(metadata_bytes.decode('utf-8'))
            filename = metadata['filename']
            ct_len = metadata['ct_len']

            print(f"Receiving file: {filename}")

            # Receive KEM ciphertext
            ciphertext = b''
            while len(ciphertext) < ct_len:
                chunk = conn.recv(min(BUFFER_SIZE, ct_len - len(ciphertext)))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving ciphertext")
                ciphertext += chunk

            # Receive nonce
            nonce = b''
            while len(nonce) < 12:
                chunk = conn.recv(12 - len(nonce))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving nonce")
                nonce += chunk

            # Receive encrypted data
            encrypted_data = b''
            print("Receiving encrypted data...")
            while True:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                encrypted_data += chunk
                print(f"\rReceived: {len(encrypted_data)} bytes", end='', flush=True)

            print("\n\nDecrypting...")

            # Decrypt
            with oqs.KeyEncapsulation(kem_alg, secret_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
            aes_key = _derive_aes_key(shared_secret)
            aesgcm = AESGCM(aes_key)
            decrypted = aesgcm.decrypt(nonce, encrypted_data, None)

            # Save decrypted file
            output_path = output_dir / filename
            output_path.write_bytes(decrypted)
            print(f"File received and decrypted: {output_path}")


def send_directory_direct(
    dir_path: Path,
    host: str,
    port: int,
    recipient_public_key: bytes,
    kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Send an encrypted directory directly to a receiver via TCP socket.

    Args:
        dir_path: Path to the directory to send.
        host: IP address or hostname of the receiver.
        port: Port number to connect to.
        recipient_public_key: Public key of the recipient.
        kem_alg: KEM algorithm to use.
    """
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {dir_path}")

    # Collect all files
    files = []
    for root, dirs, filenames in os.walk(dir_path):
        for filename in filenames:
            file_path = Path(root) / filename
            relative_path = file_path.relative_to(dir_path)
            files.append((file_path, str(relative_path)))

    if not files:
        print("No files to send in directory")
        return

    print(f"Preparing to send {len(files)} files...")

    # Connect to receiver
    print(f"Connecting to {host}:{port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        print("Connected!")

        # Send directory metadata
        dir_metadata = {
            "type": "directory",
            "file_count": len(files),
            "kem_alg": kem_alg,
        }
        meta_bytes = json.dumps(dir_metadata).encode('utf-8')
        sock.sendall(struct.pack("!I", len(meta_bytes)))
        sock.sendall(meta_bytes)

        # Send each file
        for idx, (file_path, relative_path) in enumerate(files, 1):
            print(f"\n[{idx}/{len(files)}] Sending {relative_path}...")

            # Encrypt file
            data = file_path.read_bytes()
            with oqs.KeyEncapsulation(kem_alg) as kem:
                ciphertext, shared_secret = kem.encap_secret(recipient_public_key)
            aes_key = _derive_aes_key(shared_secret)
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(aes_key)
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            # Send file metadata
            file_metadata = {
                "filename": relative_path,
                "ct_len": len(ciphertext),
            }
            file_meta_bytes = json.dumps(file_metadata).encode('utf-8')
            sock.sendall(struct.pack("!I", len(file_meta_bytes)))
            sock.sendall(file_meta_bytes)

            # Send encrypted file data
            sock.sendall(ciphertext)
            sock.sendall(nonce)
            sock.sendall(encrypted_data)

            print(f"  Sent {len(encrypted_data)} bytes")

        print("\nAll files sent successfully!")


def receive_directory_direct(
    port: int,
    output_dir: Path,
    secret_key: bytes,
    kem_alg: str = DEFAULT_KEM_ALG
) -> None:
    """Receive an encrypted directory via TCP socket and decrypt it.

    Args:
        port: Port number to listen on.
        output_dir: Directory where the decrypted files will be saved.
        secret_key: Secret key for decryption.
        kem_alg: KEM algorithm to use.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('0.0.0.0', port))
        server_sock.listen(1)

        print(f"Listening on port {port}...")
        print("Waiting for incoming directory transfer...")

        conn, addr = server_sock.accept()
        with conn:
            print(f"Connection from {addr[0]}:{addr[1]}")

            # Receive directory metadata
            meta_len_bytes = conn.recv(4)
            if len(meta_len_bytes) != 4:
                raise ValueError("Failed to receive metadata length")
            meta_len = struct.unpack("!I", meta_len_bytes)[0]

            metadata_bytes = conn.recv(meta_len)
            metadata = json.loads(metadata_bytes.decode('utf-8'))

            if metadata.get("type") != "directory":
                raise ValueError("Expected directory transfer")

            file_count = metadata['file_count']
            print(f"Receiving {file_count} files...\n")

            # Receive each file
            for idx in range(file_count):
                # Receive file metadata
                file_meta_len = struct.unpack("!I", conn.recv(4))[0]
                file_meta_bytes = conn.recv(file_meta_len)
                file_metadata = json.loads(file_meta_bytes.decode('utf-8'))

                filename = file_metadata['filename']
                ct_len = file_metadata['ct_len']

                print(f"[{idx+1}/{file_count}] Receiving {filename}...")

                # Receive encrypted file data
                ciphertext = b''
                while len(ciphertext) < ct_len:
                    chunk = conn.recv(min(BUFFER_SIZE, ct_len - len(ciphertext)))
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    ciphertext += chunk

                nonce = conn.recv(12)

                # Receive encrypted data (read until we get the complete encrypted file)
                # We need to know the size, but for simplicity we'll read a reasonable amount
                encrypted_data = b''
                conn.settimeout(1.0)  # Set timeout to detect end of this file's data
                try:
                    while True:
                        chunk = conn.recv(BUFFER_SIZE)
                        if not chunk:
                            break
                        encrypted_data += chunk
                        # Try to decrypt to see if we have all data
                        try:
                            with oqs.KeyEncapsulation(kem_alg, secret_key) as kem:
                                shared_secret = kem.decap_secret(ciphertext)
                            aes_key = _derive_aes_key(shared_secret)
                            aesgcm = AESGCM(aes_key)
                            decrypted = aesgcm.decrypt(nonce, encrypted_data, None)
                            # If we got here, decryption succeeded
                            break
                        except:
                            # Need more data
                            continue
                except socket.timeout:
                    pass  # Expected when we've read all data for this file
                finally:
                    conn.settimeout(None)

                # Decrypt
                with oqs.KeyEncapsulation(kem_alg, secret_key) as kem:
                    shared_secret = kem.decap_secret(ciphertext)
                aes_key = _derive_aes_key(shared_secret)
                aesgcm = AESGCM(aes_key)
                decrypted = aesgcm.decrypt(nonce, encrypted_data, None)

                # Save file
                output_path = output_dir / filename
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(decrypted)
                print(f"  Decrypted and saved: {output_path}")

            print(f"\nAll {file_count} files received successfully!")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
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

    # send command (direct transfer)
    parser_send = subparsers.add_parser(
        "send", help="Send file/directory directly to a receiver (peer-to-peer)"
    )
    parser_send.add_argument("src", type=Path, help="File or directory to send")
    parser_send.add_argument("host", type=str, help="Receiver's IP address or hostname")
    parser_send.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"Port number (default: {DEFAULT_PORT})"
    )
    parser_send.add_argument(
        "--recipient-key", type=Path, required=True, help="Path to recipient's public key file"
    )
    parser_send.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )

    # receive command (direct transfer)
    parser_recv = subparsers.add_parser(
        "receive", help="Receive file/directory directly from a sender (peer-to-peer)"
    )
    parser_recv.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"Port to listen on (default: {DEFAULT_PORT})"
    )
    parser_recv.add_argument(
        "--out", type=Path, default=Path("."), help="Output directory (default: current directory)"
    )
    parser_recv.add_argument(
        "--key-dir", type=Path, default=Path("keys"), help="Directory containing private.key"
    )
    parser_recv.add_argument(
        "--alg", type=str, default=DEFAULT_KEM_ALG, help=f"KEM algorithm (default: {DEFAULT_KEM_ALG})"
    )

    # upload command (rclone)
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

    # download command (rclone)
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

    args = parser.parse_args()

    try:
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

        elif args.command == "decrypt":
            if args.src.is_file():
                sec_key = (args.key_dir / "private.key").read_bytes()
                decrypt_file(args.src, args.dst, sec_key, args.alg)
                print(f"Decrypted {args.src} -> {args.dst}")
            else:
                sec_key = (args.key_dir / "private.key").read_bytes()
                decrypt_directory(args.src, args.dst, sec_key, args.alg)

        elif args.command == "send":
            recipient_pub_key = args.recipient_key.read_bytes()
            if args.src.is_file():
                send_file_direct(args.src, args.host, args.port, recipient_pub_key, args.alg)
            else:
                send_directory_direct(args.src, args.host, args.port, recipient_pub_key, args.alg)

        elif args.command == "receive":
            sec_key = (args.key_dir / "private.key").read_bytes()
            # This will automatically handle both file and directory
            receive_directory_direct(args.port, args.out, sec_key, args.alg)

        elif args.command == "encrypt-upload":
            encrypt_and_upload(args.src, args.remote, args.key_dir, args.alg)

        elif args.command == "download-decrypt":
            download_and_decrypt(args.remote, args.dst, args.key_dir, args.alg)

        else:
            parser.error("Unknown command")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
