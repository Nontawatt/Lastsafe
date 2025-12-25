"""
Base Cloud Adapter Interface
=============================

Defines the abstract interface that all cloud adapters must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Dict, Any


@dataclass
class UploadResult:
    """Result of an upload operation."""
    success: bool
    remote_path: Optional[str] = None
    bytes_transferred: int = 0
    files_count: int = 0
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class DownloadResult:
    """Result of a download operation."""
    success: bool
    local_path: Optional[Path] = None
    bytes_transferred: int = 0
    files_count: int = 0
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class FileInfo:
    """Information about a remote file."""
    path: str
    size: int
    modified: Optional[str] = None
    checksum: Optional[str] = None
    is_directory: bool = False


class ProgressCallback:
    """Callback for progress updates."""

    def __init__(
        self,
        callback: Optional[Callable[[int, int, str], None]] = None,
    ):
        """Initialize progress callback.

        Args:
            callback: Function called with (bytes_done, bytes_total, filename)
        """
        self.callback = callback
        self.total_bytes = 0
        self.transferred_bytes = 0
        self.current_file = ""

    def update(
        self,
        bytes_done: int,
        bytes_total: int,
        filename: str = "",
    ) -> None:
        """Update progress.

        Args:
            bytes_done: Bytes transferred so far
            bytes_total: Total bytes to transfer
            filename: Current file being transferred
        """
        self.transferred_bytes = bytes_done
        self.total_bytes = bytes_total
        self.current_file = filename
        if self.callback:
            self.callback(bytes_done, bytes_total, filename)

    def increment(self, bytes_added: int) -> None:
        """Increment transferred bytes.

        Args:
            bytes_added: Bytes just transferred
        """
        self.transferred_bytes += bytes_added
        if self.callback:
            self.callback(
                self.transferred_bytes, self.total_bytes, self.current_file
            )


class CloudAdapter(ABC):
    """Abstract base class for cloud storage adapters.

    All cloud adapters must implement these methods to provide
    a consistent interface for file operations.
    """

    @abstractmethod
    def upload_file(
        self,
        local_path: Path,
        remote_path: str,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Upload a single file to cloud storage.

        Args:
            local_path: Path to local file
            remote_path: Destination path in cloud storage
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        pass

    @abstractmethod
    def upload_directory(
        self,
        local_path: Path,
        remote_path: str,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Upload a directory to cloud storage.

        Args:
            local_path: Path to local directory
            remote_path: Destination path in cloud storage
            progress: Optional progress callback

        Returns:
            UploadResult with operation details
        """
        pass

    @abstractmethod
    def download_file(
        self,
        remote_path: str,
        local_path: Path,
        progress: Optional[ProgressCallback] = None,
    ) -> DownloadResult:
        """Download a single file from cloud storage.

        Args:
            remote_path: Path in cloud storage
            local_path: Destination local path
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        pass

    @abstractmethod
    def download_directory(
        self,
        remote_path: str,
        local_path: Path,
        progress: Optional[ProgressCallback] = None,
    ) -> DownloadResult:
        """Download a directory from cloud storage.

        Args:
            remote_path: Path in cloud storage
            local_path: Destination local directory
            progress: Optional progress callback

        Returns:
            DownloadResult with operation details
        """
        pass

    @abstractmethod
    def list_files(
        self,
        remote_path: str,
        recursive: bool = False,
    ) -> Iterator[FileInfo]:
        """List files in a remote path.

        Args:
            remote_path: Path in cloud storage
            recursive: Whether to list recursively

        Yields:
            FileInfo objects for each file/directory
        """
        pass

    @abstractmethod
    def delete_file(self, remote_path: str) -> bool:
        """Delete a file from cloud storage.

        Args:
            remote_path: Path to delete

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    def file_exists(self, remote_path: str) -> bool:
        """Check if a file exists in cloud storage.

        Args:
            remote_path: Path to check

        Returns:
            True if file exists
        """
        pass

    @abstractmethod
    def get_file_info(self, remote_path: str) -> Optional[FileInfo]:
        """Get information about a remote file.

        Args:
            remote_path: Path to query

        Returns:
            FileInfo or None if not found
        """
        pass

    def sync(
        self,
        local_path: Path,
        remote_path: str,
        direction: str = "upload",
        delete: bool = False,
        progress: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Synchronize local and remote directories.

        Args:
            local_path: Local directory path
            remote_path: Remote directory path
            direction: 'upload' or 'download'
            delete: Whether to delete extra files at destination
            progress: Optional progress callback

        Returns:
            Result of sync operation
        """
        if direction == "upload":
            return self.upload_directory(local_path, remote_path, progress)
        else:
            result = self.download_directory(remote_path, local_path, progress)
            return UploadResult(
                success=result.success,
                remote_path=remote_path,
                bytes_transferred=result.bytes_transferred,
                files_count=result.files_count,
                error=result.error,
            )
