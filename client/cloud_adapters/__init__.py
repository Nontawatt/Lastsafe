"""
Cloud Provider Adapters for Lastsafe Client
============================================

Provides adapters for various cloud storage providers:
- AWS S3
- Google Cloud Storage
- Azure Blob Storage
- Rclone (for any rclone-supported backend)
"""

from .base import CloudAdapter, UploadResult, DownloadResult
from .rclone_adapter import RcloneAdapter
from .s3_adapter import S3Adapter
from .gcs_adapter import GCSAdapter
from .azure_adapter import AzureAdapter

__all__ = [
    "CloudAdapter",
    "UploadResult",
    "DownloadResult",
    "RcloneAdapter",
    "S3Adapter",
    "GCSAdapter",
    "AzureAdapter",
]


def get_adapter(provider: str, **kwargs) -> CloudAdapter:
    """Factory function to get the appropriate adapter.

    Args:
        provider: Name of the cloud provider ('s3', 'gcs', 'azure', 'rclone')
        **kwargs: Provider-specific configuration

    Returns:
        Appropriate CloudAdapter instance
    """
    adapters = {
        "s3": S3Adapter,
        "aws": S3Adapter,
        "gcs": GCSAdapter,
        "google": GCSAdapter,
        "azure": AzureAdapter,
        "rclone": RcloneAdapter,
    }

    provider_lower = provider.lower()
    if provider_lower not in adapters:
        raise ValueError(
            f"Unknown provider: {provider}. "
            f"Supported: {list(adapters.keys())}"
        )

    return adapters[provider_lower](**kwargs)
