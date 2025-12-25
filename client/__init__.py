"""
Lastsafe Client - Post-Quantum Encrypted Cloud Storage Client
=============================================================

A modular client library for encrypting data locally before uploading
to cloud storage providers, using post-quantum cryptography (ML-KEM)
combined with AES-256-GCM symmetric encryption.

Main Components:
- SecureClient: Main entry point for all operations
- EncryptionEngine: Core encryption/decryption logic
- KeyManager: Key generation, storage, and rotation
- CloudAdapters: Adapters for various cloud providers

Example Usage:
    from client import SecureClient

    # Initialize client
    client = SecureClient(config_path="~/.lastsafe/config.yaml")

    # Generate keys
    client.generate_keys()

    # Encrypt and upload
    client.encrypt_upload("./my_data", "s3://my-bucket/backup")

    # Download and decrypt
    client.download_decrypt("s3://my-bucket/backup", "./restored_data")
"""

from .secure_client import SecureClient
from .encryption_engine import EncryptionEngine
from .key_manager import KeyManager
from .config import ClientConfig

__version__ = "2.0.0"
__all__ = [
    "SecureClient",
    "EncryptionEngine",
    "KeyManager",
    "ClientConfig",
]
