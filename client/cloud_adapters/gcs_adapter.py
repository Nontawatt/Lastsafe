"""
Google Cloud Storage Adapter
=============================

Direct adapter for Google Cloud Storage.
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


class GCSAdapter(CloudAdapter):
    """Cloud adapter for Google Cloud Storage.

    Requires google-cloud-storage: pip install google-cloud-storage

    Authentication options:
    - GOOGLE_APPLICATION_CREDENTIALS environment variable
    - credentials_file parameter
    - Default application credentials (gcloud auth)
    """

    def __init__(
        self,
        bucket: Optional[str] = None,
        project: Optional[str] = None,
        credentials_file: Optional[str] = None,
    ):
        """Initialize the GCS adapter.

        Args:
            bucket: GCS bucket name
            project: Google Cloud project ID
            credentials_file: Path to service account JSON file
        """
        try:
            from google.cloud import storage
            from google.oauth2 import service_account
        except ImportError:
            raise ImportError(
                "google-cloud-storage is required for GCS support. "
                "Install with: pip install google-cloud-storage"
            )

        self.bucket_name = bucket
        self.project = project

        # Set up credentials
        if credentials_file:
            credentials = service_account.Credentials.from_service_account_file(
                credentials_file
            )
            self.client = storage.Client(
                project=project, credentials=credentials
            )
        elif os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            self.client = storage.Client(project=project)
        else:
            # Use default credentials
            self.client = storage.Client(project=project)

        self._storage = storage

    def _get_bucket(self, bucket_name: Optional[str] = None):
        """Get a bucket object.

        Args:
            bucket_name: Bucket name (uses default if None)

        Returns:
            Bucket object
        """
        name = bucket_name or self.bucket_name
        if not name:
            raise ValueError("Bucket name required")
        return self.client.bucket(name)

    def _parse_path(self, path: str) -> tuple:
        """Parse a path into bucket and blob name.

        Args:
            path: Path like 'bucket/path' or 'gs://bucket/path'

        Returns:
            Tuple of (bucket_name, blob_path)
        """
        # Handle gs:// prefix
        if path.startswith("gs://"):
            path = path[5:]

        # Use default bucket if no bucket in path
        if "/" not in path and self.bucket_name:
            return self.bucket_name, path

        parts = path.split("/", 1)
        bucket = parts[0]
        blob_path = parts[1] if len(parts) > 1 else ""
        return bucket, blob_path

    def upload_file(
        self,
        local_path: Path,
        remote_path: str,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Upload a file to GCS.

        Args:
            local_path: Path to local file
            remote_path: Destination GCS path
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        try:
            bucket_name, blob_path = self._parse_path(remote_path)
            bucket = self._get_bucket(bucket_name)
            blob = bucket.blob(blob_path)

            file_size = local_path.stat().st_size

            # Upload with resumable upload for large files
            blob.upload_from_filename(
                str(local_path),
                timeout=300,
            )

            if progress:
                progress.update(file_size, file_size, str(local_path))

            return UploadResult(
                success=True,
                remote_path=f"gs://{bucket_name}/{blob_path}",
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
        """Upload a directory to GCS.

        Args:
            local_path: Path to local directory
            remote_path: Destination GCS path
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        try:
            bucket_name, prefix = self._parse_path(remote_path)
            bucket = self._get_bucket(bucket_name)

            total_bytes = 0
            file_count = 0

            for file_path in local_path.rglob("*"):
                if file_path.is_file():
                    relative = file_path.relative_to(local_path)
                    blob_path = f"{prefix}/{relative}" if prefix else str(relative)

                    blob = bucket.blob(blob_path)
                    file_size = file_path.stat().st_size

                    blob.upload_from_filename(str(file_path), timeout=300)

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
                remote_path=f"gs://{bucket_name}/{prefix}",
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
        """Download a file from GCS.

        Args:
            remote_path: GCS path
            local_path: Destination local path
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        try:
            bucket_name, blob_path = self._parse_path(remote_path)
            bucket = self._get_bucket(bucket_name)
            blob = bucket.blob(blob_path)

            local_path.parent.mkdir(parents=True, exist_ok=True)

            blob.download_to_filename(str(local_path))
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
        """Download a directory from GCS.

        Args:
            remote_path: GCS path
            local_path: Destination local directory
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        try:
            bucket_name, prefix = self._parse_path(remote_path)
            bucket = self._get_bucket(bucket_name)

            local_path.mkdir(parents=True, exist_ok=True)

            total_bytes = 0
            file_count = 0

            blobs = bucket.list_blobs(prefix=prefix)
            for blob in blobs:
                # Calculate relative path
                relative = blob.name[len(prefix):].lstrip("/") if prefix else blob.name
                if not relative:
                    continue

                dest_path = local_path / relative
                dest_path.parent.mkdir(parents=True, exist_ok=True)

                blob.download_to_filename(str(dest_path))
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
        """List files in a GCS path.

        Args:
            remote_path: GCS path
            recursive: Whether to list recursively

        Yields:
            FileInfo objects for each file
        """
        bucket_name, prefix = self._parse_path(remote_path)
        bucket = self._get_bucket(bucket_name)

        delimiter = None if recursive else "/"
        blobs = bucket.list_blobs(prefix=prefix, delimiter=delimiter)

        for blob in blobs:
            yield FileInfo(
                path=blob.name,
                size=blob.size or 0,
                modified=blob.updated.isoformat() if blob.updated else None,
                checksum=blob.md5_hash,
            )

        # Include prefixes (directories) for non-recursive listing
        if not recursive and hasattr(blobs, "prefixes"):
            for prefix in blobs.prefixes:
                yield FileInfo(
                    path=prefix,
                    size=0,
                    is_directory=True,
                )

    def delete_file(self, remote_path: str) -> bool:
        """Delete a file from GCS.

        Args:
            remote_path: GCS path to delete

        Returns:
            True if successful
        """
        try:
            bucket_name, blob_path = self._parse_path(remote_path)
            bucket = self._get_bucket(bucket_name)
            blob = bucket.blob(blob_path)
            blob.delete()
            return True
        except Exception:
            return False

    def file_exists(self, remote_path: str) -> bool:
        """Check if a file exists in GCS.

        Args:
            remote_path: GCS path to check

        Returns:
            True if file exists
        """
        try:
            bucket_name, blob_path = self._parse_path(remote_path)
            bucket = self._get_bucket(bucket_name)
            blob = bucket.blob(blob_path)
            return blob.exists()
        except Exception:
            return False

    def get_file_info(self, remote_path: str) -> Optional[FileInfo]:
        """Get file info from GCS.

        Args:
            remote_path: GCS path

        Returns:
            FileInfo or None if not found
        """
        try:
            bucket_name, blob_path = self._parse_path(remote_path)
            bucket = self._get_bucket(bucket_name)
            blob = bucket.get_blob(blob_path)

            if blob is None:
                return None

            return FileInfo(
                path=blob.name,
                size=blob.size or 0,
                modified=blob.updated.isoformat() if blob.updated else None,
                checksum=blob.md5_hash,
            )
        except Exception:
            return None

    def create_bucket(
        self,
        bucket_name: str,
        location: str = "US",
    ) -> bool:
        """Create a new GCS bucket.

        Args:
            bucket_name: Name for the new bucket
            location: Storage location

        Returns:
            True if successful
        """
        try:
            bucket = self.client.bucket(bucket_name)
            bucket.location = location
            self.client.create_bucket(bucket)
            return True
        except Exception:
            return False
