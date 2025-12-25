"""
Azure Blob Storage Adapter
===========================

Direct adapter for Microsoft Azure Blob Storage.
"""

import os
from pathlib import Path
from typing import Iterator, Optional

from .base import (
    CloudAdapter,
    UploadResult,
    DownloadResult,
    FileInfo,
    ProgressCallback,
)


class AzureAdapter(CloudAdapter):
    """Cloud adapter for Azure Blob Storage.

    Requires azure-storage-blob: pip install azure-storage-blob

    Authentication options:
    - Connection string (AZURE_STORAGE_CONNECTION_STRING)
    - Account name + key
    - Account name + SAS token
    """

    def __init__(
        self,
        container: Optional[str] = None,
        account_name: Optional[str] = None,
        account_key: Optional[str] = None,
        connection_string: Optional[str] = None,
        sas_token: Optional[str] = None,
    ):
        """Initialize the Azure adapter.

        Args:
            container: Azure container name
            account_name: Storage account name
            account_key: Storage account key
            connection_string: Full connection string
            sas_token: SAS token for authentication
        """
        try:
            from azure.storage.blob import BlobServiceClient, ContainerClient
        except ImportError:
            raise ImportError(
                "azure-storage-blob is required for Azure support. "
                "Install with: pip install azure-storage-blob"
            )

        self.container_name = container
        self._BlobServiceClient = BlobServiceClient
        self._ContainerClient = ContainerClient

        # Set up authentication
        conn_str = connection_string or os.environ.get(
            "AZURE_STORAGE_CONNECTION_STRING"
        )

        if conn_str:
            self.service_client = BlobServiceClient.from_connection_string(conn_str)
        elif account_name:
            account_url = f"https://{account_name}.blob.core.windows.net"

            if account_key or os.environ.get("AZURE_STORAGE_KEY"):
                key = account_key or os.environ["AZURE_STORAGE_KEY"]
                self.service_client = BlobServiceClient(
                    account_url=account_url,
                    credential=key,
                )
            elif sas_token:
                self.service_client = BlobServiceClient(
                    account_url=f"{account_url}?{sas_token}"
                )
            else:
                # Try DefaultAzureCredential
                from azure.identity import DefaultAzureCredential
                credential = DefaultAzureCredential()
                self.service_client = BlobServiceClient(
                    account_url=account_url,
                    credential=credential,
                )
        else:
            raise ValueError(
                "Either connection_string or account_name must be provided"
            )

    def _get_container_client(self, container_name: Optional[str] = None):
        """Get a container client.

        Args:
            container_name: Container name (uses default if None)

        Returns:
            ContainerClient object
        """
        name = container_name or self.container_name
        if not name:
            raise ValueError("Container name required")
        return self.service_client.get_container_client(name)

    def _parse_path(self, path: str) -> tuple:
        """Parse a path into container and blob name.

        Args:
            path: Path like 'container/path' or 'azure://container/path'

        Returns:
            Tuple of (container_name, blob_path)
        """
        # Handle azure:// or https:// prefix
        if path.startswith("azure://"):
            path = path[8:]
        elif path.startswith("https://"):
            # Parse full URL
            parts = path.split("/", 3)
            if len(parts) >= 4:
                path = "/".join(parts[3:])

        # Use default container if no container in path
        if "/" not in path and self.container_name:
            return self.container_name, path

        parts = path.split("/", 1)
        container = parts[0]
        blob_path = parts[1] if len(parts) > 1 else ""
        return container, blob_path

    def upload_file(
        self,
        local_path: Path,
        remote_path: str,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Upload a file to Azure Blob Storage.

        Args:
            local_path: Path to local file
            remote_path: Destination Azure path
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        try:
            container_name, blob_path = self._parse_path(remote_path)
            container_client = self._get_container_client(container_name)
            blob_client = container_client.get_blob_client(blob_path)

            file_size = local_path.stat().st_size

            with open(local_path, "rb") as data:
                blob_client.upload_blob(data, overwrite=True)

            if progress:
                progress.update(file_size, file_size, str(local_path))

            return UploadResult(
                success=True,
                remote_path=f"azure://{container_name}/{blob_path}",
                bytes_transferred=file_size,
                files_count=1,
            )

        except Exception as e:
            return UploadResult(
                success=False,
                error=str(e),
            )

    def upload_directory(
        self,
        local_path: Path,
        remote_path: str,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Upload a directory to Azure Blob Storage.

        Args:
            local_path: Path to local directory
            remote_path: Destination Azure path
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        try:
            container_name, prefix = self._parse_path(remote_path)
            container_client = self._get_container_client(container_name)

            total_bytes = 0
            file_count = 0

            for file_path in local_path.rglob("*"):
                if file_path.is_file():
                    relative = file_path.relative_to(local_path)
                    blob_path = f"{prefix}/{relative}" if prefix else str(relative)

                    blob_client = container_client.get_blob_client(blob_path)
                    file_size = file_path.stat().st_size

                    with open(file_path, "rb") as data:
                        blob_client.upload_blob(data, overwrite=True)

                    if progress:
                        progress.update(
                            total_bytes + file_size,
                            total_bytes + file_size,
                            str(relative),
                        )

                    total_bytes += file_size
                    file_count += 1

            return UploadResult(
                success=True,
                remote_path=f"azure://{container_name}/{prefix}",
                bytes_transferred=total_bytes,
                files_count=file_count,
            )

        except Exception as e:
            return UploadResult(
                success=False,
                error=str(e),
            )

    def download_file(
        self,
        remote_path: str,
        local_path: Path,
        progress: Optional[ProgressCallback] = None,
    ) -> DownloadResult:
        """Download a file from Azure Blob Storage.

        Args:
            remote_path: Azure path
            local_path: Destination local path
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        try:
            container_name, blob_path = self._parse_path(remote_path)
            container_client = self._get_container_client(container_name)
            blob_client = container_client.get_blob_client(blob_path)

            local_path.parent.mkdir(parents=True, exist_ok=True)

            with open(local_path, "wb") as download_file:
                download_stream = blob_client.download_blob()
                download_file.write(download_stream.readall())

            file_size = local_path.stat().st_size

            if progress:
                progress.update(file_size, file_size, blob_path)

            return DownloadResult(
                success=True,
                local_path=local_path,
                bytes_transferred=file_size,
                files_count=1,
            )

        except Exception as e:
            return DownloadResult(
                success=False,
                error=str(e),
            )

    def download_directory(
        self,
        remote_path: str,
        local_path: Path,
        progress: Optional[ProgressCallback] = None,
    ) -> DownloadResult:
        """Download a directory from Azure Blob Storage.

        Args:
            remote_path: Azure path
            local_path: Destination local directory
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        try:
            container_name, prefix = self._parse_path(remote_path)
            container_client = self._get_container_client(container_name)

            local_path.mkdir(parents=True, exist_ok=True)

            total_bytes = 0
            file_count = 0

            blobs = container_client.list_blobs(name_starts_with=prefix)
            for blob in blobs:
                # Calculate relative path
                relative = blob.name[len(prefix):].lstrip("/") if prefix else blob.name
                if not relative:
                    continue

                dest_path = local_path / relative
                dest_path.parent.mkdir(parents=True, exist_ok=True)

                blob_client = container_client.get_blob_client(blob.name)
                with open(dest_path, "wb") as download_file:
                    download_stream = blob_client.download_blob()
                    download_file.write(download_stream.readall())

                file_size = dest_path.stat().st_size

                if progress:
                    progress.update(
                        total_bytes + file_size,
                        total_bytes + file_size,
                        relative,
                    )

                total_bytes += file_size
                file_count += 1

            return DownloadResult(
                success=True,
                local_path=local_path,
                bytes_transferred=total_bytes,
                files_count=file_count,
            )

        except Exception as e:
            return DownloadResult(
                success=False,
                error=str(e),
            )

    def list_files(
        self,
        remote_path: str,
        recursive: bool = False,
    ) -> Iterator[FileInfo]:
        """List files in an Azure path.

        Args:
            remote_path: Azure path
            recursive: Whether to list recursively

        Yields:
            FileInfo objects for each file
        """
        container_name, prefix = self._parse_path(remote_path)
        container_client = self._get_container_client(container_name)

        if recursive:
            blobs = container_client.list_blobs(name_starts_with=prefix)
        else:
            blobs = container_client.walk_blobs(name_starts_with=prefix)

        for blob in blobs:
            # Check if it's a prefix (directory)
            if hasattr(blob, "prefix"):
                yield FileInfo(
                    path=blob.prefix,
                    size=0,
                    is_directory=True,
                )
            else:
                yield FileInfo(
                    path=blob.name,
                    size=blob.size or 0,
                    modified=blob.last_modified.isoformat() if blob.last_modified else None,
                    checksum=blob.content_settings.content_md5.hex() if blob.content_settings and blob.content_settings.content_md5 else None,
                )

    def delete_file(self, remote_path: str) -> bool:
        """Delete a file from Azure Blob Storage.

        Args:
            remote_path: Azure path to delete

        Returns:
            True if successful
        """
        try:
            container_name, blob_path = self._parse_path(remote_path)
            container_client = self._get_container_client(container_name)
            blob_client = container_client.get_blob_client(blob_path)
            blob_client.delete_blob()
            return True
        except Exception:
            return False

    def file_exists(self, remote_path: str) -> bool:
        """Check if a file exists in Azure Blob Storage.

        Args:
            remote_path: Azure path to check

        Returns:
            True if file exists
        """
        try:
            container_name, blob_path = self._parse_path(remote_path)
            container_client = self._get_container_client(container_name)
            blob_client = container_client.get_blob_client(blob_path)
            return blob_client.exists()
        except Exception:
            return False

    def get_file_info(self, remote_path: str) -> Optional[FileInfo]:
        """Get file info from Azure Blob Storage.

        Args:
            remote_path: Azure path

        Returns:
            FileInfo or None if not found
        """
        try:
            container_name, blob_path = self._parse_path(remote_path)
            container_client = self._get_container_client(container_name)
            blob_client = container_client.get_blob_client(blob_path)

            properties = blob_client.get_blob_properties()
            return FileInfo(
                path=blob_path,
                size=properties.size or 0,
                modified=properties.last_modified.isoformat() if properties.last_modified else None,
                checksum=properties.content_settings.content_md5.hex() if properties.content_settings and properties.content_settings.content_md5 else None,
            )
        except Exception:
            return None

    def create_container(self, container_name: str) -> bool:
        """Create a new Azure container.

        Args:
            container_name: Name for the new container

        Returns:
            True if successful
        """
        try:
            container_client = self.service_client.get_container_client(container_name)
            container_client.create_container()
            return True
        except Exception:
            return False
