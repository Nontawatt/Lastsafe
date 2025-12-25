"""
Rclone Cloud Adapter
=====================

Adapter that uses rclone as the backend for cloud operations.
Supports any cloud provider that rclone supports.
"""

import json
import subprocess
from pathlib import Path
from typing import Iterator, Optional

from .base import (
    CloudAdapter,
    UploadResult,
    DownloadResult,
    FileInfo,
    ProgressCallback,
)


class RcloneAdapter(CloudAdapter):
    """Cloud adapter using rclone as backend.

    Rclone supports over 40 cloud storage providers including:
    - Google Drive
    - Amazon S3
    - Dropbox
    - OneDrive
    - Azure Blob Storage
    - Google Cloud Storage
    - And many more...

    This adapter wraps rclone commands to provide a consistent interface.
    """

    def __init__(
        self,
        remote_name: Optional[str] = None,
        config_file: Optional[Path] = None,
        rclone_path: str = "rclone",
    ):
        """Initialize the rclone adapter.

        Args:
            remote_name: Default remote name (e.g., 'gdrive', 'myS3')
            config_file: Path to rclone config file
            rclone_path: Path to rclone binary
        """
        self.remote_name = remote_name
        self.config_file = config_file
        self.rclone_path = rclone_path
        self._verify_rclone()

    def _verify_rclone(self) -> None:
        """Verify that rclone is installed and accessible."""
        try:
            result = subprocess.run(
                [self.rclone_path, "version"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError("rclone returned non-zero exit code")
        except FileNotFoundError:
            raise RuntimeError(
                f"rclone not found at {self.rclone_path}. "
                "Please install rclone: https://rclone.org/install/"
            )

    def _build_command(self, *args: str) -> list:
        """Build rclone command with common options.

        Args:
            *args: Command arguments

        Returns:
            Complete command list
        """
        cmd = [self.rclone_path]
        if self.config_file:
            cmd.extend(["--config", str(self.config_file)])
        cmd.extend(args)
        return cmd

    def _run_command(
        self,
        *args: str,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run an rclone command.

        Args:
            *args: Command arguments
            capture_output: Whether to capture output

        Returns:
            CompletedProcess result
        """
        cmd = self._build_command(*args)
        return subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=False,
        )

    def _normalize_path(self, remote_path: str) -> str:
        """Normalize remote path to include remote name if needed.

        Args:
            remote_path: Remote path, possibly without remote prefix

        Returns:
            Path with remote prefix
        """
        if ":" not in remote_path and self.remote_name:
            return f"{self.remote_name}:{remote_path}"
        return remote_path

    def upload_file(
        self,
        local_path: Path,
        remote_path: str,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Upload a single file using rclone copy.

        Args:
            local_path: Path to local file
            remote_path: Destination path
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        remote_path = self._normalize_path(remote_path)

        args = ["copy", str(local_path), remote_path]
        if progress:
            args.append("--progress")

        result = self._run_command(*args, capture_output=not progress)

        if result.returncode == 0:
            file_size = local_path.stat().st_size
            return UploadResult(
                success=True,
                remote_path=remote_path,
                bytes_transferred=file_size,
                files_count=1,
            )
        else:
            return UploadResult(
                success=False,
                error=result.stderr or "Upload failed",
            )

    def upload_directory(
        self,
        local_path: Path,
        remote_path: str,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Upload a directory using rclone copy.

        Args:
            local_path: Path to local directory
            remote_path: Destination path
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        remote_path = self._normalize_path(remote_path)

        args = ["copy", str(local_path), remote_path]
        if progress:
            args.append("--progress")

        result = self._run_command(*args, capture_output=not progress)

        if result.returncode == 0:
            # Count files and total size
            total_size = 0
            file_count = 0
            for f in local_path.rglob("*"):
                if f.is_file():
                    total_size += f.stat().st_size
                    file_count += 1

            return UploadResult(
                success=True,
                remote_path=remote_path,
                bytes_transferred=total_size,
                files_count=file_count,
            )
        else:
            return UploadResult(
                success=False,
                error=result.stderr or "Upload failed",
            )

    def download_file(
        self,
        remote_path: str,
        local_path: Path,
        progress: Optional[ProgressCallback] = None,
    ) -> DownloadResult:
        """Download a single file using rclone copy.

        Args:
            remote_path: Path in cloud storage
            local_path: Destination local path
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        remote_path = self._normalize_path(remote_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)

        args = ["copy", remote_path, str(local_path.parent)]
        if progress:
            args.append("--progress")

        result = self._run_command(*args, capture_output=not progress)

        if result.returncode == 0:
            file_size = local_path.stat().st_size if local_path.exists() else 0
            return DownloadResult(
                success=True,
                local_path=local_path,
                bytes_transferred=file_size,
                files_count=1,
            )
        else:
            return DownloadResult(
                success=False,
                error=result.stderr or "Download failed",
            )

    def download_directory(
        self,
        remote_path: str,
        local_path: Path,
        progress: Optional[ProgressCallback] = None,
    ) -> DownloadResult:
        """Download a directory using rclone copy.

        Args:
            remote_path: Path in cloud storage
            local_path: Destination local directory
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        remote_path = self._normalize_path(remote_path)
        local_path.mkdir(parents=True, exist_ok=True)

        args = ["copy", remote_path, str(local_path)]
        if progress:
            args.append("--progress")

        result = self._run_command(*args, capture_output=not progress)

        if result.returncode == 0:
            # Count downloaded files
            total_size = 0
            file_count = 0
            for f in local_path.rglob("*"):
                if f.is_file():
                    total_size += f.stat().st_size
                    file_count += 1

            return DownloadResult(
                success=True,
                local_path=local_path,
                bytes_transferred=total_size,
                files_count=file_count,
            )
        else:
            return DownloadResult(
                success=False,
                error=result.stderr or "Download failed",
            )

    def list_files(
        self,
        remote_path: str,
        recursive: bool = False,
    ) -> Iterator[FileInfo]:
        """List files using rclone lsjson.

        Args:
            remote_path: Path in cloud storage
            recursive: Whether to list recursively

        Yields:
            FileInfo objects for each file/directory
        """
        remote_path = self._normalize_path(remote_path)

        args = ["lsjson", remote_path]
        if recursive:
            args.append("--recursive")

        result = self._run_command(*args)

        if result.returncode != 0:
            return

        try:
            items = json.loads(result.stdout)
            for item in items:
                yield FileInfo(
                    path=item.get("Path", ""),
                    size=item.get("Size", 0),
                    modified=item.get("ModTime"),
                    is_directory=item.get("IsDir", False),
                )
        except json.JSONDecodeError:
            pass

    def delete_file(self, remote_path: str) -> bool:
        """Delete a file using rclone deletefile.

        Args:
            remote_path: Path to delete

        Returns:
            True if successful
        """
        remote_path = self._normalize_path(remote_path)
        result = self._run_command("deletefile", remote_path)
        return result.returncode == 0

    def file_exists(self, remote_path: str) -> bool:
        """Check if file exists using rclone lsf.

        Args:
            remote_path: Path to check

        Returns:
            True if file exists
        """
        remote_path = self._normalize_path(remote_path)
        result = self._run_command("lsf", remote_path)
        return result.returncode == 0 and bool(result.stdout.strip())

    def get_file_info(self, remote_path: str) -> Optional[FileInfo]:
        """Get file info using rclone lsjson.

        Args:
            remote_path: Path to query

        Returns:
            FileInfo or None if not found
        """
        remote_path = self._normalize_path(remote_path)
        result = self._run_command("lsjson", remote_path)

        if result.returncode != 0:
            return None

        try:
            items = json.loads(result.stdout)
            if items:
                item = items[0]
                return FileInfo(
                    path=item.get("Path", ""),
                    size=item.get("Size", 0),
                    modified=item.get("ModTime"),
                    checksum=item.get("Hashes", {}).get("md5"),
                    is_directory=item.get("IsDir", False),
                )
        except (json.JSONDecodeError, IndexError):
            pass

        return None

    def list_remotes(self) -> list:
        """List configured rclone remotes.

        Returns:
            List of remote names
        """
        result = self._run_command("listremotes")
        if result.returncode == 0:
            return [r.rstrip(":") for r in result.stdout.strip().split("\n") if r]
        return []
