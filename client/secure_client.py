"""
SecureClient - Main Entry Point for Lastsafe Client
=====================================================

The SecureClient class is the main interface for all encryption
and cloud operations. It integrates:
- Encryption Engine (PQC + AES-256-GCM)
- Key Management
- Cloud Adapters
- Progress Tracking
"""

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional, List, Dict, Any, Union

from .config import ClientConfig
from .encryption_engine import EncryptionEngine, EncryptionResult, DecryptionResult
from .key_manager import KeyManager, KeyPair
from .cloud_adapters import get_adapter, CloudAdapter
from .cloud_adapters.base import (
    UploadResult,
    DownloadResult,
    FileInfo,
    ProgressCallback,
)


# Configure logging
logger = logging.getLogger("lastsafe.client")


@dataclass
class TransferResult:
    """Result of an encrypt-upload or download-decrypt operation."""
    success: bool
    files_processed: int = 0
    bytes_processed: int = 0
    remote_path: Optional[str] = None
    local_path: Optional[Path] = None
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class SecureClient:
    """Main client for encrypted cloud storage operations.

    This class provides a unified interface for:
    - Key generation and management
    - Local file/directory encryption and decryption
    - Encrypted upload to cloud storage
    - Download and decryption from cloud storage

    Example:
        >>> from client import SecureClient
        >>>
        >>> # Initialize with default config
        >>> client = SecureClient()
        >>>
        >>> # Generate keys (first time only)
        >>> client.generate_keys()
        >>>
        >>> # Encrypt and upload
        >>> result = client.encrypt_upload(
        ...     "./my_data",
        ...     "s3://my-bucket/backup",
        ...     provider="s3"
        ... )
        >>>
        >>> # Download and decrypt
        >>> result = client.download_decrypt(
        ...     "s3://my-bucket/backup",
        ...     "./restored_data",
        ...     provider="s3"
        ... )
    """

    def __init__(
        self,
        config: Optional[ClientConfig] = None,
        config_path: Optional[Path] = None,
    ):
        """Initialize the SecureClient.

        Args:
            config: ClientConfig instance (takes precedence over config_path)
            config_path: Path to YAML configuration file
        """
        # Load configuration
        if config is not None:
            self.config = config
        elif config_path is not None:
            self.config = ClientConfig.load(config_path)
        else:
            self.config = ClientConfig.load()

        # Set up logging
        self._setup_logging()

        # Initialize components
        self.key_manager = KeyManager(
            key_dir=self.config.keys.key_dir,
            algorithm=self.config.encryption.kem_algorithm,
            rotation_days=self.config.keys.key_rotation_days,
        )

        self.encryption_engine = EncryptionEngine(
            kem_algorithm=self.config.encryption.kem_algorithm,
            chunk_size=self.config.encryption.chunk_size,
        )

        # Cloud adapter cache
        self._adapters: Dict[str, CloudAdapter] = {}

        logger.info("SecureClient initialized")

    def _setup_logging(self) -> None:
        """Configure logging based on config."""
        level = getattr(logging, self.config.logging.level.upper(), logging.INFO)
        logger.setLevel(level)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        if self.config.logging.log_file:
            file_handler = logging.FileHandler(self.config.logging.log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    def _get_adapter(
        self,
        provider: Optional[str] = None,
        **kwargs,
    ) -> CloudAdapter:
        """Get or create a cloud adapter.

        Args:
            provider: Cloud provider name
            **kwargs: Additional provider-specific options

        Returns:
            CloudAdapter instance
        """
        provider = provider or self.config.cloud.default_provider

        # Check cache
        cache_key = f"{provider}_{hash(frozenset(kwargs.items()))}"
        if cache_key in self._adapters:
            return self._adapters[cache_key]

        # Build adapter options from config
        adapter_kwargs = dict(kwargs)

        if provider in ("s3", "aws"):
            if not adapter_kwargs.get("bucket"):
                adapter_kwargs["bucket"] = self.config.cloud.s3_bucket
            if not adapter_kwargs.get("region"):
                adapter_kwargs["region"] = self.config.cloud.s3_region
            if not adapter_kwargs.get("access_key") and self.config.cloud.s3_access_key:
                adapter_kwargs["access_key"] = self.config.cloud.s3_access_key
                adapter_kwargs["secret_key"] = self.config.cloud.s3_secret_key

        elif provider in ("gcs", "google"):
            if not adapter_kwargs.get("bucket"):
                adapter_kwargs["bucket"] = self.config.cloud.gcs_bucket
            if not adapter_kwargs.get("project"):
                adapter_kwargs["project"] = self.config.cloud.gcs_project
            if not adapter_kwargs.get("credentials_file"):
                adapter_kwargs["credentials_file"] = self.config.cloud.gcs_credentials_file

        elif provider == "azure":
            if not adapter_kwargs.get("container"):
                adapter_kwargs["container"] = self.config.cloud.azure_container
            if not adapter_kwargs.get("account_name"):
                adapter_kwargs["account_name"] = self.config.cloud.azure_account_name
            if not adapter_kwargs.get("account_key"):
                adapter_kwargs["account_key"] = self.config.cloud.azure_account_key
            if not adapter_kwargs.get("connection_string"):
                adapter_kwargs["connection_string"] = self.config.cloud.azure_connection_string

        elif provider == "rclone":
            if not adapter_kwargs.get("remote_name"):
                adapter_kwargs["remote_name"] = self.config.cloud.rclone_remote

        adapter = get_adapter(provider, **adapter_kwargs)
        self._adapters[cache_key] = adapter
        return adapter

    # =========================================================================
    # Key Management
    # =========================================================================

    def generate_keys(
        self,
        description: Optional[str] = None,
        expires_in_days: Optional[int] = None,
    ) -> KeyPair:
        """Generate a new key pair.

        Args:
            description: Optional description for the keys
            expires_in_days: Days until key expires

        Returns:
            Generated KeyPair
        """
        logger.info("Generating new key pair...")
        keypair = self.key_manager.generate_keys(
            description=description,
            expires_in_days=expires_in_days,
        )
        logger.info(f"Keys generated with ID: {keypair.metadata.key_id}")
        logger.info(f"Fingerprint: {keypair.metadata.fingerprint}")
        return keypair

    def rotate_keys(
        self,
        description: Optional[str] = None,
    ) -> KeyPair:
        """Rotate keys (backup old, generate new).

        Args:
            description: Optional description for new keys

        Returns:
            New KeyPair
        """
        logger.info("Rotating keys...")
        keypair = self.key_manager.rotate_keys(description=description)
        logger.info(f"New keys generated with ID: {keypair.metadata.key_id}")
        return keypair

    def check_keys(self) -> Dict[str, Any]:
        """Check the health of current keys.

        Returns:
            Health check results
        """
        return self.key_manager.check_key_health()

    def export_public_key(self, output_path: Path) -> None:
        """Export public key to a file.

        Args:
            output_path: Where to save the public key
        """
        self.key_manager.export_public_key(output_path)
        logger.info(f"Public key exported to {output_path}")

    # =========================================================================
    # Local Encryption/Decryption
    # =========================================================================

    def encrypt(
        self,
        source: Union[Path, str],
        destination: Union[Path, str],
        use_streaming: Optional[bool] = None,
    ) -> EncryptionResult:
        """Encrypt a file or directory locally.

        Args:
            source: Path to source file or directory
            destination: Path for encrypted output
            use_streaming: Use streaming for large files

        Returns:
            EncryptionResult with operation details
        """
        source = Path(source)
        destination = Path(destination)

        if use_streaming is None:
            use_streaming = self.config.encryption.use_streaming

        public_key = self.key_manager.load_public_key()

        if source.is_file():
            logger.info(f"Encrypting file: {source}")
            result = self.encryption_engine.encrypt_file(
                source, destination, public_key, use_streaming
            )
            if result.success:
                logger.info(f"Encrypted to: {destination}")
            else:
                logger.error(f"Encryption failed: {result.error}")
            return result
        else:
            logger.info(f"Encrypting directory: {source}")
            return self._encrypt_directory(source, destination, public_key, use_streaming)

    def _encrypt_directory(
        self,
        source: Path,
        destination: Path,
        public_key: bytes,
        use_streaming: bool,
    ) -> EncryptionResult:
        """Encrypt a directory recursively.

        Args:
            source: Source directory
            destination: Destination directory
            public_key: Public key for encryption
            use_streaming: Use streaming for large files

        Returns:
            EncryptionResult with combined stats
        """
        destination.mkdir(parents=True, exist_ok=True)

        total_bytes = 0
        file_count = 0
        errors = []

        for file_path in source.rglob("*"):
            if file_path.is_file():
                # Skip hidden files if configured
                if not self.config.include_hidden_files and file_path.name.startswith("."):
                    continue

                relative = file_path.relative_to(source)
                dest_path = destination / relative

                # Determine if streaming should be used
                file_size = file_path.stat().st_size
                use_stream = use_streaming and file_size > self.config.encryption.streaming_threshold

                result = self.encryption_engine.encrypt_file(
                    file_path, dest_path, public_key, use_stream
                )

                if result.success:
                    total_bytes += result.bytes_processed
                    file_count += 1
                else:
                    errors.append(f"{file_path}: {result.error}")

        if errors:
            logger.warning(f"Encryption completed with {len(errors)} errors")
            return EncryptionResult(
                success=len(errors) == 0,
                output_path=destination,
                bytes_processed=total_bytes,
                error="; ".join(errors) if errors else None,
            )

        logger.info(f"Encrypted {file_count} files ({total_bytes} bytes)")
        return EncryptionResult(
            success=True,
            output_path=destination,
            bytes_processed=total_bytes,
        )

    def decrypt(
        self,
        source: Union[Path, str],
        destination: Union[Path, str],
    ) -> DecryptionResult:
        """Decrypt a file or directory locally.

        Args:
            source: Path to encrypted file or directory
            destination: Path for decrypted output

        Returns:
            DecryptionResult with operation details
        """
        source = Path(source)
        destination = Path(destination)

        private_key = self.key_manager.load_private_key()

        if source.is_file():
            logger.info(f"Decrypting file: {source}")
            result = self.encryption_engine.decrypt_file(source, destination, private_key)
            if result.success:
                logger.info(f"Decrypted to: {destination}")
            else:
                logger.error(f"Decryption failed: {result.error}")
            return result
        else:
            logger.info(f"Decrypting directory: {source}")
            return self._decrypt_directory(source, destination, private_key)

    def _decrypt_directory(
        self,
        source: Path,
        destination: Path,
        private_key: bytes,
    ) -> DecryptionResult:
        """Decrypt a directory recursively.

        Args:
            source: Source directory with encrypted files
            destination: Destination directory
            private_key: Private key for decryption

        Returns:
            DecryptionResult with combined stats
        """
        destination.mkdir(parents=True, exist_ok=True)

        total_bytes = 0
        file_count = 0
        errors = []

        for file_path in source.rglob("*"):
            if file_path.is_file():
                relative = file_path.relative_to(source)
                dest_path = destination / relative

                result = self.encryption_engine.decrypt_file(
                    file_path, dest_path, private_key
                )

                if result.success:
                    total_bytes += result.bytes_processed
                    file_count += 1
                else:
                    errors.append(f"{file_path}: {result.error}")

        if errors:
            logger.warning(f"Decryption completed with {len(errors)} errors")
            return DecryptionResult(
                success=len(errors) == 0,
                output_path=destination,
                bytes_processed=total_bytes,
                error="; ".join(errors) if errors else None,
            )

        logger.info(f"Decrypted {file_count} files ({total_bytes} bytes)")
        return DecryptionResult(
            success=True,
            output_path=destination,
            bytes_processed=total_bytes,
        )

    # =========================================================================
    # Cloud Operations
    # =========================================================================

    def encrypt_upload(
        self,
        source: Union[Path, str],
        remote_path: str,
        provider: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        **provider_kwargs,
    ) -> TransferResult:
        """Encrypt a file/directory and upload to cloud storage.

        Args:
            source: Local path to encrypt and upload
            remote_path: Remote destination path
            provider: Cloud provider name
            progress_callback: Optional callback for progress updates
            **provider_kwargs: Additional provider-specific options

        Returns:
            TransferResult with operation details
        """
        source = Path(source)
        logger.info(f"Starting encrypt-upload: {source} -> {remote_path}")

        # Load public key
        public_key = self.key_manager.load_public_key()

        # Get cloud adapter
        adapter = self._get_adapter(provider, **provider_kwargs)

        # Create temporary directory for encrypted files
        temp_dir = self.config.temp_dir or None
        with tempfile.TemporaryDirectory(dir=temp_dir) as tmpdir:
            tmp_path = Path(tmpdir)

            # Encrypt files
            logger.info("Encrypting files...")
            if source.is_file():
                encrypted_path = tmp_path / source.name
                enc_result = self.encryption_engine.encrypt_file(
                    source, encrypted_path, public_key,
                    use_streaming=self.config.encryption.use_streaming
                )
                if not enc_result.success:
                    return TransferResult(
                        success=False,
                        errors=[f"Encryption failed: {enc_result.error}"],
                    )
                bytes_encrypted = enc_result.bytes_processed
                files_encrypted = 1
            else:
                enc_result = self._encrypt_directory(
                    source, tmp_path, public_key,
                    use_streaming=self.config.encryption.use_streaming
                )
                if not enc_result.success:
                    return TransferResult(
                        success=False,
                        errors=[f"Encryption failed: {enc_result.error}"],
                    )
                bytes_encrypted = enc_result.bytes_processed
                files_encrypted = sum(1 for _ in tmp_path.rglob("*") if _.is_file())

            logger.info(f"Encrypted {files_encrypted} files")

            # Upload encrypted files
            logger.info("Uploading to cloud...")
            progress = None
            if progress_callback:
                progress = ProgressCallback(progress_callback)

            if source.is_file():
                upload_result = adapter.upload_file(
                    encrypted_path, remote_path, progress
                )
            else:
                upload_result = adapter.upload_directory(
                    tmp_path, remote_path, progress
                )

            if not upload_result.success:
                return TransferResult(
                    success=False,
                    errors=[f"Upload failed: {upload_result.error}"],
                )

        logger.info(f"Upload complete: {remote_path}")
        return TransferResult(
            success=True,
            files_processed=files_encrypted,
            bytes_processed=bytes_encrypted,
            remote_path=remote_path,
        )

    def download_decrypt(
        self,
        remote_path: str,
        destination: Union[Path, str],
        provider: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        **provider_kwargs,
    ) -> TransferResult:
        """Download from cloud storage and decrypt.

        Args:
            remote_path: Remote path to download
            destination: Local destination path
            provider: Cloud provider name
            progress_callback: Optional callback for progress updates
            **provider_kwargs: Additional provider-specific options

        Returns:
            TransferResult with operation details
        """
        destination = Path(destination)
        logger.info(f"Starting download-decrypt: {remote_path} -> {destination}")

        # Load private key
        private_key = self.key_manager.load_private_key()

        # Get cloud adapter
        adapter = self._get_adapter(provider, **provider_kwargs)

        # Create temporary directory for downloaded files
        temp_dir = self.config.temp_dir or None
        with tempfile.TemporaryDirectory(dir=temp_dir) as tmpdir:
            tmp_path = Path(tmpdir)

            # Download files
            logger.info("Downloading from cloud...")
            progress = None
            if progress_callback:
                progress = ProgressCallback(progress_callback)

            # Check if it's a single file or directory
            file_info = adapter.get_file_info(remote_path)
            if file_info and not file_info.is_directory:
                downloaded_path = tmp_path / Path(remote_path).name
                download_result = adapter.download_file(
                    remote_path, downloaded_path, progress
                )
            else:
                download_result = adapter.download_directory(
                    remote_path, tmp_path, progress
                )

            if not download_result.success:
                return TransferResult(
                    success=False,
                    errors=[f"Download failed: {download_result.error}"],
                )

            logger.info(f"Downloaded {download_result.files_count} files")

            # Decrypt files
            logger.info("Decrypting files...")
            if file_info and not file_info.is_directory:
                destination.parent.mkdir(parents=True, exist_ok=True)
                dec_result = self.encryption_engine.decrypt_file(
                    downloaded_path, destination, private_key
                )
                if not dec_result.success:
                    return TransferResult(
                        success=False,
                        errors=[f"Decryption failed: {dec_result.error}"],
                    )
                bytes_decrypted = dec_result.bytes_processed
                files_decrypted = 1
            else:
                dec_result = self._decrypt_directory(
                    tmp_path, destination, private_key
                )
                if not dec_result.success:
                    return TransferResult(
                        success=False,
                        errors=[f"Decryption failed: {dec_result.error}"],
                    )
                bytes_decrypted = dec_result.bytes_processed
                files_decrypted = sum(1 for _ in destination.rglob("*") if _.is_file())

        logger.info(f"Download and decrypt complete: {destination}")
        return TransferResult(
            success=True,
            files_processed=files_decrypted,
            bytes_processed=bytes_decrypted,
            local_path=destination,
        )

    def list_remote(
        self,
        remote_path: str,
        provider: Optional[str] = None,
        recursive: bool = False,
        **provider_kwargs,
    ) -> Iterator[FileInfo]:
        """List files in remote storage.

        Args:
            remote_path: Remote path to list
            provider: Cloud provider name
            recursive: Whether to list recursively
            **provider_kwargs: Additional provider-specific options

        Yields:
            FileInfo objects for each file
        """
        adapter = self._get_adapter(provider, **provider_kwargs)
        yield from adapter.list_files(remote_path, recursive)

    def delete_remote(
        self,
        remote_path: str,
        provider: Optional[str] = None,
        **provider_kwargs,
    ) -> bool:
        """Delete a file from remote storage.

        Args:
            remote_path: Remote path to delete
            provider: Cloud provider name
            **provider_kwargs: Additional provider-specific options

        Returns:
            True if successful
        """
        adapter = self._get_adapter(provider, **provider_kwargs)
        return adapter.delete_file(remote_path)

    def sync(
        self,
        local_path: Union[Path, str],
        remote_path: str,
        direction: str = "upload",
        provider: Optional[str] = None,
        **provider_kwargs,
    ) -> TransferResult:
        """Synchronize local and remote directories.

        Args:
            local_path: Local directory path
            remote_path: Remote directory path
            direction: 'upload' or 'download'
            provider: Cloud provider name
            **provider_kwargs: Additional provider-specific options

        Returns:
            TransferResult with operation details
        """
        local_path = Path(local_path)

        if direction == "upload":
            return self.encrypt_upload(local_path, remote_path, provider, **provider_kwargs)
        elif direction == "download":
            return self.download_decrypt(remote_path, local_path, provider, **provider_kwargs)
        else:
            raise ValueError(f"Invalid direction: {direction}")
