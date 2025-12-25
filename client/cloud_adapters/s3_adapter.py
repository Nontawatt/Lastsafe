"""
AWS S3 Cloud Adapter
=====================

Direct adapter for Amazon S3 and S3-compatible storage services.
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


class S3ProgressCallback:
    """S3 transfer progress callback wrapper."""

    def __init__(self, callback: Optional[ProgressCallback], total_size: int):
        self.callback = callback
        self.total_size = total_size
        self._transferred = 0

    def __call__(self, bytes_amount: int):
        self._transferred += bytes_amount
        if self.callback:
            self.callback.update(self._transferred, self.total_size, "")


class S3Adapter(CloudAdapter):
    """Cloud adapter for Amazon S3 and S3-compatible storage.

    Requires boto3 to be installed: pip install boto3

    Supports:
    - Amazon S3
    - MinIO
    - DigitalOcean Spaces
    - Wasabi
    - Backblaze B2 (S3 compatible)
    - Any S3-compatible storage
    """

    def __init__(
        self,
        bucket: Optional[str] = None,
        region: str = "us-east-1",
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        profile_name: Optional[str] = None,
    ):
        """Initialize the S3 adapter.

        Args:
            bucket: S3 bucket name
            region: AWS region
            access_key: AWS access key ID (or use AWS_ACCESS_KEY_ID env)
            secret_key: AWS secret access key (or use AWS_SECRET_ACCESS_KEY env)
            endpoint_url: Custom endpoint for S3-compatible services
            profile_name: AWS profile name from ~/.aws/credentials
        """
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise ImportError(
                "boto3 is required for S3 support. "
                "Install with: pip install boto3"
            )

        self.bucket = bucket
        self.region = region

        # Build session kwargs
        session_kwargs = {}
        if profile_name:
            session_kwargs["profile_name"] = profile_name

        # Create session
        session = boto3.Session(**session_kwargs)

        # Build client kwargs
        client_kwargs = {
            "region_name": region,
            "config": Config(signature_version="s3v4"),
        }

        if access_key and secret_key:
            client_kwargs["aws_access_key_id"] = access_key
            client_kwargs["aws_secret_access_key"] = secret_key
        elif os.environ.get("AWS_ACCESS_KEY_ID"):
            client_kwargs["aws_access_key_id"] = os.environ["AWS_ACCESS_KEY_ID"]
            client_kwargs["aws_secret_access_key"] = os.environ.get(
                "AWS_SECRET_ACCESS_KEY", ""
            )

        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        self.s3 = session.client("s3", **client_kwargs)
        self._boto3 = boto3

    def _parse_path(self, path: str) -> tuple:
        """Parse a path into bucket and key.

        Args:
            path: Path like 'bucket/key' or 's3://bucket/key'

        Returns:
            Tuple of (bucket, key)
        """
        # Handle s3:// prefix
        if path.startswith("s3://"):
            path = path[5:]

        # Use default bucket if no bucket in path
        if "/" not in path and self.bucket:
            return self.bucket, path

        parts = path.split("/", 1)
        bucket = parts[0]
        key = parts[1] if len(parts) > 1 else ""
        return bucket, key

    def upload_file(
        self,
        local_path: Path,
        remote_path: str,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Upload a file to S3.

        Args:
            local_path: Path to local file
            remote_path: Destination S3 path
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        try:
            bucket, key = self._parse_path(remote_path)
            file_size = local_path.stat().st_size

            # Prepare callback
            callback = None
            if progress:
                callback = S3ProgressCallback(progress, file_size)

            # Upload
            self.s3.upload_file(
                str(local_path),
                bucket,
                key,
                Callback=callback,
            )

            return UploadResult(
                success=True,
                remote_path=f"s3://{bucket}/{key}",
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
        """Upload a directory to S3.

        Args:
            local_path: Path to local directory
            remote_path: Destination S3 path
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        try:
            bucket, prefix = self._parse_path(remote_path)
            total_bytes = 0
            file_count = 0

            for file_path in local_path.rglob("*"):
                if file_path.is_file():
                    relative = file_path.relative_to(local_path)
                    key = f"{prefix}/{relative}" if prefix else str(relative)

                    file_size = file_path.stat().st_size
                    callback = None
                    if progress:
                        callback = S3ProgressCallback(progress, file_size)

                    self.s3.upload_file(
                        str(file_path),
                        bucket,
                        key,
                        Callback=callback,
                    )

                    total_bytes += file_size
                    file_count += 1

            return UploadResult(
                success=True,
                remote_path=f"s3://{bucket}/{prefix}",
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
        """Download a file from S3.

        Args:
            remote_path: S3 path
            local_path: Destination local path
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        try:
            bucket, key = self._parse_path(remote_path)
            local_path.parent.mkdir(parents=True, exist_ok=True)

            # Get file size first
            head = self.s3.head_object(Bucket=bucket, Key=key)
            file_size = head["ContentLength"]

            callback = None
            if progress:
                callback = S3ProgressCallback(progress, file_size)

            self.s3.download_file(
                bucket,
                key,
                str(local_path),
                Callback=callback,
            )

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
        """Download a directory from S3.

        Args:
            remote_path: S3 path
            local_path: Destination local directory
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        try:
            bucket, prefix = self._parse_path(remote_path)
            local_path.mkdir(parents=True, exist_ok=True)

            total_bytes = 0
            file_count = 0

            # List and download all objects
            paginator = self.s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    file_size = obj["Size"]

                    # Calculate relative path
                    relative = key[len(prefix):].lstrip("/") if prefix else key
                    if not relative:
                        continue

                    dest_path = local_path / relative
                    dest_path.parent.mkdir(parents=True, exist_ok=True)

                    callback = None
                    if progress:
                        callback = S3ProgressCallback(progress, file_size)

                    self.s3.download_file(
                        bucket,
                        key,
                        str(dest_path),
                        Callback=callback,
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
        """List files in an S3 path.

        Args:
            remote_path: S3 path
            recursive: Whether to list recursively

        Yields:
            FileInfo objects for each file
        """
        bucket, prefix = self._parse_path(remote_path)

        paginator = self.s3.get_paginator("list_objects_v2")
        kwargs = {"Bucket": bucket}
        if prefix:
            kwargs["Prefix"] = prefix
        if not recursive:
            kwargs["Delimiter"] = "/"

        for page in paginator.paginate(**kwargs):
            # Directories (common prefixes)
            for common_prefix in page.get("CommonPrefixes", []):
                yield FileInfo(
                    path=common_prefix["Prefix"],
                    size=0,
                    is_directory=True,
                )

            # Files
            for obj in page.get("Contents", []):
                yield FileInfo(
                    path=obj["Key"],
                    size=obj["Size"],
                    modified=obj["LastModified"].isoformat(),
                    checksum=obj.get("ETag", "").strip('"'),
                )

    def delete_file(self, remote_path: str) -> bool:
        """Delete a file from S3.

        Args:
            remote_path: S3 path to delete

        Returns:
            True if successful
        """
        try:
            bucket, key = self._parse_path(remote_path)
            self.s3.delete_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def file_exists(self, remote_path: str) -> bool:
        """Check if a file exists in S3.

        Args:
            remote_path: S3 path to check

        Returns:
            True if file exists
        """
        try:
            bucket, key = self._parse_path(remote_path)
            self.s3.head_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def get_file_info(self, remote_path: str) -> Optional[FileInfo]:
        """Get file info from S3.

        Args:
            remote_path: S3 path

        Returns:
            FileInfo or None if not found
        """
        try:
            bucket, key = self._parse_path(remote_path)
            head = self.s3.head_object(Bucket=bucket, Key=key)
            return FileInfo(
                path=key,
                size=head["ContentLength"],
                modified=head["LastModified"].isoformat(),
                checksum=head.get("ETag", "").strip('"'),
            )
        except Exception:
            return None

    def create_bucket(self, bucket_name: str) -> bool:
        """Create a new S3 bucket.

        Args:
            bucket_name: Name for the new bucket

        Returns:
            True if successful
        """
        try:
            if self.region == "us-east-1":
                self.s3.create_bucket(Bucket=bucket_name)
            else:
                self.s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": self.region},
                )
            return True
        except Exception:
            return False
