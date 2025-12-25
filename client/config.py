"""
Configuration Management for Lastsafe Client
=============================================

Provides configuration management including:
- YAML configuration file support
- Environment variable overrides
- Secure defaults
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any
import os
import yaml


@dataclass
class EncryptionConfig:
    """Encryption-related configuration."""
    kem_algorithm: str = "ML-KEM-512"
    chunk_size: int = 64 * 1024 * 1024  # 64MB chunks for streaming
    use_streaming: bool = True  # Use streaming for large files
    streaming_threshold: int = 100 * 1024 * 1024  # 100MB threshold


@dataclass
class KeyConfig:
    """Key management configuration."""
    key_dir: Path = field(default_factory=lambda: Path.home() / ".lastsafe" / "keys")
    public_key_file: str = "public.key"
    private_key_file: str = "private.key"
    key_backup_enabled: bool = True
    key_rotation_days: int = 365  # Recommended key rotation period


@dataclass
class CloudConfig:
    """Cloud provider configuration."""
    default_provider: str = "rclone"  # rclone, s3, gcs, azure

    # AWS S3 settings
    s3_bucket: Optional[str] = None
    s3_region: str = "us-east-1"
    s3_access_key: Optional[str] = None
    s3_secret_key: Optional[str] = None

    # Google Cloud Storage settings
    gcs_bucket: Optional[str] = None
    gcs_project: Optional[str] = None
    gcs_credentials_file: Optional[str] = None

    # Azure Blob Storage settings
    azure_container: Optional[str] = None
    azure_account_name: Optional[str] = None
    azure_account_key: Optional[str] = None
    azure_connection_string: Optional[str] = None

    # Rclone settings (for legacy compatibility)
    rclone_remote: Optional[str] = None


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    log_file: Optional[Path] = None
    show_progress: bool = True
    verbose: bool = False


@dataclass
class ClientConfig:
    """Main client configuration."""
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    keys: KeyConfig = field(default_factory=KeyConfig)
    cloud: CloudConfig = field(default_factory=CloudConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # Temporary directory for encrypted files
    temp_dir: Optional[Path] = None

    # Metadata settings
    preserve_metadata: bool = True
    include_hidden_files: bool = False

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "ClientConfig":
        """Load configuration from YAML file with environment variable overrides.

        Args:
            config_path: Path to YAML configuration file. If None, uses default
                        location (~/.lastsafe/config.yaml)

        Returns:
            ClientConfig instance with loaded settings
        """
        config = cls()

        # Determine config file path
        if config_path is None:
            config_path = Path.home() / ".lastsafe" / "config.yaml"
        else:
            config_path = Path(config_path)

        # Load from YAML if exists
        if config_path.exists():
            with open(config_path, "r") as f:
                yaml_config = yaml.safe_load(f) or {}
            config._apply_yaml_config(yaml_config)

        # Apply environment variable overrides
        config._apply_env_overrides()

        return config

    def _apply_yaml_config(self, yaml_config: Dict[str, Any]) -> None:
        """Apply YAML configuration values."""
        # Encryption settings
        if "encryption" in yaml_config:
            enc = yaml_config["encryption"]
            if "kem_algorithm" in enc:
                self.encryption.kem_algorithm = enc["kem_algorithm"]
            if "chunk_size" in enc:
                self.encryption.chunk_size = enc["chunk_size"]
            if "use_streaming" in enc:
                self.encryption.use_streaming = enc["use_streaming"]
            if "streaming_threshold" in enc:
                self.encryption.streaming_threshold = enc["streaming_threshold"]

        # Key settings
        if "keys" in yaml_config:
            keys = yaml_config["keys"]
            if "key_dir" in keys:
                self.keys.key_dir = Path(keys["key_dir"]).expanduser()
            if "key_rotation_days" in keys:
                self.keys.key_rotation_days = keys["key_rotation_days"]

        # Cloud settings
        if "cloud" in yaml_config:
            cloud = yaml_config["cloud"]
            if "default_provider" in cloud:
                self.cloud.default_provider = cloud["default_provider"]
            if "s3" in cloud:
                s3 = cloud["s3"]
                self.cloud.s3_bucket = s3.get("bucket")
                self.cloud.s3_region = s3.get("region", "us-east-1")
            if "gcs" in cloud:
                gcs = cloud["gcs"]
                self.cloud.gcs_bucket = gcs.get("bucket")
                self.cloud.gcs_project = gcs.get("project")
                self.cloud.gcs_credentials_file = gcs.get("credentials_file")
            if "azure" in cloud:
                azure = cloud["azure"]
                self.cloud.azure_container = azure.get("container")
                self.cloud.azure_account_name = azure.get("account_name")
            if "rclone" in cloud:
                self.cloud.rclone_remote = cloud["rclone"].get("remote")

        # Logging settings
        if "logging" in yaml_config:
            log = yaml_config["logging"]
            if "level" in log:
                self.logging.level = log["level"]
            if "log_file" in log:
                self.logging.log_file = Path(log["log_file"]).expanduser()
            if "show_progress" in log:
                self.logging.show_progress = log["show_progress"]
            if "verbose" in log:
                self.logging.verbose = log["verbose"]

        # General settings
        if "temp_dir" in yaml_config:
            self.temp_dir = Path(yaml_config["temp_dir"]).expanduser()
        if "preserve_metadata" in yaml_config:
            self.preserve_metadata = yaml_config["preserve_metadata"]
        if "include_hidden_files" in yaml_config:
            self.include_hidden_files = yaml_config["include_hidden_files"]

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        # Encryption settings
        if kem_alg := os.environ.get("LASTSAFE_KEM_ALGORITHM"):
            self.encryption.kem_algorithm = kem_alg

        # Key directory
        if key_dir := os.environ.get("LASTSAFE_KEY_DIR"):
            self.keys.key_dir = Path(key_dir).expanduser()

        # Cloud settings
        if provider := os.environ.get("LASTSAFE_CLOUD_PROVIDER"):
            self.cloud.default_provider = provider

        # AWS S3
        if s3_bucket := os.environ.get("LASTSAFE_S3_BUCKET"):
            self.cloud.s3_bucket = s3_bucket
        if s3_region := os.environ.get("LASTSAFE_S3_REGION"):
            self.cloud.s3_region = s3_region
        if s3_access := os.environ.get("AWS_ACCESS_KEY_ID"):
            self.cloud.s3_access_key = s3_access
        if s3_secret := os.environ.get("AWS_SECRET_ACCESS_KEY"):
            self.cloud.s3_secret_key = s3_secret

        # Google Cloud
        if gcs_bucket := os.environ.get("LASTSAFE_GCS_BUCKET"):
            self.cloud.gcs_bucket = gcs_bucket
        if gcs_project := os.environ.get("GOOGLE_CLOUD_PROJECT"):
            self.cloud.gcs_project = gcs_project
        if gcs_creds := os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            self.cloud.gcs_credentials_file = gcs_creds

        # Azure
        if azure_container := os.environ.get("LASTSAFE_AZURE_CONTAINER"):
            self.cloud.azure_container = azure_container
        if azure_account := os.environ.get("AZURE_STORAGE_ACCOUNT"):
            self.cloud.azure_account_name = azure_account
        if azure_key := os.environ.get("AZURE_STORAGE_KEY"):
            self.cloud.azure_account_key = azure_key
        if azure_conn := os.environ.get("AZURE_STORAGE_CONNECTION_STRING"):
            self.cloud.azure_connection_string = azure_conn

        # Logging
        if log_level := os.environ.get("LASTSAFE_LOG_LEVEL"):
            self.logging.level = log_level
        if verbose := os.environ.get("LASTSAFE_VERBOSE"):
            self.logging.verbose = verbose.lower() in ("true", "1", "yes")

    def save(self, config_path: Optional[Path] = None) -> None:
        """Save current configuration to YAML file.

        Args:
            config_path: Path where to save configuration
        """
        if config_path is None:
            config_path = Path.home() / ".lastsafe" / "config.yaml"
        else:
            config_path = Path(config_path)

        config_path.parent.mkdir(parents=True, exist_ok=True)

        config_dict = {
            "encryption": {
                "kem_algorithm": self.encryption.kem_algorithm,
                "chunk_size": self.encryption.chunk_size,
                "use_streaming": self.encryption.use_streaming,
                "streaming_threshold": self.encryption.streaming_threshold,
            },
            "keys": {
                "key_dir": str(self.keys.key_dir),
                "key_rotation_days": self.keys.key_rotation_days,
            },
            "cloud": {
                "default_provider": self.cloud.default_provider,
            },
            "logging": {
                "level": self.logging.level,
                "show_progress": self.logging.show_progress,
                "verbose": self.logging.verbose,
            },
            "preserve_metadata": self.preserve_metadata,
            "include_hidden_files": self.include_hidden_files,
        }

        # Add cloud-specific config if set
        if self.cloud.s3_bucket:
            config_dict["cloud"]["s3"] = {
                "bucket": self.cloud.s3_bucket,
                "region": self.cloud.s3_region,
            }
        if self.cloud.gcs_bucket:
            config_dict["cloud"]["gcs"] = {
                "bucket": self.cloud.gcs_bucket,
                "project": self.cloud.gcs_project,
            }
        if self.cloud.azure_container:
            config_dict["cloud"]["azure"] = {
                "container": self.cloud.azure_container,
                "account_name": self.cloud.azure_account_name,
            }
        if self.cloud.rclone_remote:
            config_dict["cloud"]["rclone"] = {
                "remote": self.cloud.rclone_remote,
            }

        if self.logging.log_file:
            config_dict["logging"]["log_file"] = str(self.logging.log_file)

        if self.temp_dir:
            config_dict["temp_dir"] = str(self.temp_dir)

        with open(config_path, "w") as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)


def get_default_config() -> ClientConfig:
    """Get a ClientConfig instance with default values."""
    return ClientConfig()
