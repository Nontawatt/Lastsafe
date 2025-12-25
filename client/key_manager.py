"""
Key Management System for Lastsafe Client
==========================================

Provides secure key management including:
- Key pair generation
- Secure key storage
- Key backup and recovery
- Key rotation support
- Key metadata tracking
"""

import json
import os
import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

try:
    import oqs
except ImportError:
    raise ImportError(
        "The 'oqs' module is required. Install with: pip install liboqs-python"
    )


@dataclass
class KeyMetadata:
    """Metadata about a keypair."""
    algorithm: str
    created_at: datetime
    key_id: str
    fingerprint: str
    expires_at: Optional[datetime] = None
    rotated_from: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "algorithm": self.algorithm,
            "created_at": self.created_at.isoformat(),
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotated_from": self.rotated_from,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyMetadata":
        """Create from dictionary."""
        return cls(
            algorithm=data["algorithm"],
            created_at=datetime.fromisoformat(data["created_at"]),
            key_id=data["key_id"],
            fingerprint=data["fingerprint"],
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            rotated_from=data.get("rotated_from"),
            description=data.get("description"),
        )

    def is_expired(self) -> bool:
        """Check if the key has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at


@dataclass
class KeyPair:
    """Represents a key pair with metadata."""
    public_key: bytes
    private_key: Optional[bytes]
    metadata: KeyMetadata


class KeyManager:
    """Manages cryptographic keys for the Lastsafe client.

    Features:
    - Generate new key pairs
    - Load and save keys securely
    - Track key metadata
    - Support key rotation
    - Backup keys
    """

    def __init__(
        self,
        key_dir: Path,
        algorithm: str = "ML-KEM-512",
        rotation_days: int = 365,
    ):
        """Initialize the key manager.

        Args:
            key_dir: Directory for key storage
            algorithm: Default KEM algorithm
            rotation_days: Days until key expiration warning
        """
        self.key_dir = Path(key_dir).expanduser()
        self.algorithm = algorithm
        self.rotation_days = rotation_days

        # File names
        self.public_key_file = "public.key"
        self.private_key_file = "private.key"
        self.metadata_file = "metadata.json"
        self.backup_dir = self.key_dir / "backups"

    def _compute_fingerprint(self, public_key: bytes) -> str:
        """Compute a fingerprint for a public key.

        Args:
            public_key: Public key bytes

        Returns:
            Hex fingerprint string
        """
        import hashlib
        digest = hashlib.sha256(public_key).hexdigest()
        # Format as XX:XX:XX:XX... (first 32 chars)
        return ":".join(digest[i:i+2] for i in range(0, 32, 2))

    def _generate_key_id(self) -> str:
        """Generate a unique key ID.

        Returns:
            Unique key ID string
        """
        return secrets.token_hex(8)

    def generate_keys(
        self,
        description: Optional[str] = None,
        expires_in_days: Optional[int] = None,
    ) -> KeyPair:
        """Generate a new key pair.

        Args:
            description: Optional description for the key
            expires_in_days: Days until key expires (None = never)

        Returns:
            KeyPair with new keys and metadata
        """
        # Create key directory
        self.key_dir.mkdir(parents=True, exist_ok=True)

        # Check for existing keys
        if self._keys_exist():
            raise FileExistsError(
                f"Keys already exist in {self.key_dir}. "
                "Use rotate_keys() to create new keys while preserving the old ones."
            )

        # Generate keys
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

        # Create metadata
        now = datetime.now()
        expires_at = None
        if expires_in_days is not None:
            expires_at = now + timedelta(days=expires_in_days)
        elif self.rotation_days:
            expires_at = now + timedelta(days=self.rotation_days)

        metadata = KeyMetadata(
            algorithm=self.algorithm,
            created_at=now,
            key_id=self._generate_key_id(),
            fingerprint=self._compute_fingerprint(public_key),
            expires_at=expires_at,
            description=description,
        )

        # Save keys and metadata
        self._save_keys(public_key, private_key, metadata)

        return KeyPair(
            public_key=public_key,
            private_key=private_key,
            metadata=metadata,
        )

    def _keys_exist(self) -> bool:
        """Check if keys already exist."""
        public_path = self.key_dir / self.public_key_file
        private_path = self.key_dir / self.private_key_file
        return public_path.exists() or private_path.exists()

    def _save_keys(
        self,
        public_key: bytes,
        private_key: bytes,
        metadata: KeyMetadata,
    ) -> None:
        """Save keys and metadata to disk.

        Args:
            public_key: Public key bytes
            private_key: Private key bytes
            metadata: Key metadata
        """
        public_path = self.key_dir / self.public_key_file
        private_path = self.key_dir / self.private_key_file
        metadata_path = self.key_dir / self.metadata_file

        # Write public key
        public_path.write_bytes(public_key)

        # Write private key with restricted permissions
        private_path.write_bytes(private_key)
        try:
            os.chmod(private_path, 0o600)
        except OSError:
            pass  # May fail on Windows

        # Write metadata
        with open(metadata_path, "w") as f:
            json.dump(metadata.to_dict(), f, indent=2)

    def load_public_key(self) -> bytes:
        """Load the public key.

        Returns:
            Public key bytes

        Raises:
            FileNotFoundError: If public key doesn't exist
        """
        public_path = self.key_dir / self.public_key_file
        if not public_path.exists():
            raise FileNotFoundError(f"Public key not found at {public_path}")
        return public_path.read_bytes()

    def load_private_key(self) -> bytes:
        """Load the private key.

        Returns:
            Private key bytes

        Raises:
            FileNotFoundError: If private key doesn't exist
        """
        private_path = self.key_dir / self.private_key_file
        if not private_path.exists():
            raise FileNotFoundError(f"Private key not found at {private_path}")
        return private_path.read_bytes()

    def load_keypair(self) -> KeyPair:
        """Load both keys and metadata.

        Returns:
            KeyPair with all data
        """
        public_key = self.load_public_key()
        private_key = self.load_private_key()
        metadata = self.load_metadata()

        return KeyPair(
            public_key=public_key,
            private_key=private_key,
            metadata=metadata,
        )

    def load_metadata(self) -> Optional[KeyMetadata]:
        """Load key metadata.

        Returns:
            KeyMetadata or None if not found
        """
        metadata_path = self.key_dir / self.metadata_file
        if not metadata_path.exists():
            # Create basic metadata for legacy keys
            if self._keys_exist():
                public_key = self.load_public_key()
                return KeyMetadata(
                    algorithm=self.algorithm,
                    created_at=datetime.fromtimestamp(
                        (self.key_dir / self.public_key_file).stat().st_mtime
                    ),
                    key_id="legacy-" + secrets.token_hex(4),
                    fingerprint=self._compute_fingerprint(public_key),
                    description="Legacy key (imported)",
                )
            return None

        with open(metadata_path, "r") as f:
            data = json.load(f)
        return KeyMetadata.from_dict(data)

    def rotate_keys(
        self,
        description: Optional[str] = None,
        expires_in_days: Optional[int] = None,
    ) -> KeyPair:
        """Rotate keys by backing up old keys and generating new ones.

        Args:
            description: Optional description for new key
            expires_in_days: Days until new key expires

        Returns:
            KeyPair with new keys
        """
        old_metadata = self.load_metadata()
        old_key_id = old_metadata.key_id if old_metadata else "unknown"

        # Backup old keys
        self._backup_keys(old_key_id)

        # Remove old keys
        for filename in [self.public_key_file, self.private_key_file, self.metadata_file]:
            path = self.key_dir / filename
            if path.exists():
                path.unlink()

        # Generate new keys
        with oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

        # Create metadata with rotation reference
        now = datetime.now()
        expires_at = None
        if expires_in_days is not None:
            expires_at = now + timedelta(days=expires_in_days)
        elif self.rotation_days:
            expires_at = now + timedelta(days=self.rotation_days)

        metadata = KeyMetadata(
            algorithm=self.algorithm,
            created_at=now,
            key_id=self._generate_key_id(),
            fingerprint=self._compute_fingerprint(public_key),
            expires_at=expires_at,
            rotated_from=old_key_id,
            description=description or f"Rotated from {old_key_id}",
        )

        # Save new keys
        self._save_keys(public_key, private_key, metadata)

        return KeyPair(
            public_key=public_key,
            private_key=private_key,
            metadata=metadata,
        )

    def _backup_keys(self, key_id: str) -> Path:
        """Backup current keys to backup directory.

        Args:
            key_id: ID of the keys being backed up

        Returns:
            Path to backup directory
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{key_id}_{timestamp}"
        backup_path = self.backup_dir / backup_name

        backup_path.mkdir(parents=True, exist_ok=True)

        for filename in [self.public_key_file, self.private_key_file, self.metadata_file]:
            src = self.key_dir / filename
            if src.exists():
                shutil.copy2(src, backup_path / filename)

        return backup_path

    def restore_backup(self, backup_name: str) -> KeyPair:
        """Restore keys from a backup.

        Args:
            backup_name: Name of the backup directory

        Returns:
            Restored KeyPair

        Raises:
            FileNotFoundError: If backup doesn't exist
        """
        backup_path = self.backup_dir / backup_name
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_name}")

        # Backup current keys first
        if self._keys_exist():
            current_metadata = self.load_metadata()
            if current_metadata:
                self._backup_keys(current_metadata.key_id)

        # Restore from backup
        for filename in [self.public_key_file, self.private_key_file, self.metadata_file]:
            src = backup_path / filename
            if src.exists():
                shutil.copy2(src, self.key_dir / filename)

        return self.load_keypair()

    def list_backups(self) -> list:
        """List available key backups.

        Returns:
            List of backup directory names
        """
        if not self.backup_dir.exists():
            return []
        return sorted([d.name for d in self.backup_dir.iterdir() if d.is_dir()])

    def export_public_key(
        self,
        output_path: Path,
        include_metadata: bool = True,
    ) -> None:
        """Export public key to a file.

        Args:
            output_path: Where to save the exported key
            include_metadata: Whether to include metadata
        """
        public_key = self.load_public_key()
        metadata = self.load_metadata()

        output_path = Path(output_path)
        output_path.write_bytes(public_key)

        if include_metadata and metadata:
            meta_path = output_path.with_suffix(".json")
            with open(meta_path, "w") as f:
                json.dump(metadata.to_dict(), f, indent=2)

    def import_public_key(
        self,
        input_path: Path,
        description: Optional[str] = None,
    ) -> bytes:
        """Import a public key from a file.

        Args:
            input_path: Path to the public key file
            description: Optional description

        Returns:
            Imported public key bytes
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Key file not found: {input_path}")

        public_key = input_path.read_bytes()

        # Try to load associated metadata
        meta_path = input_path.with_suffix(".json")
        if meta_path.exists():
            with open(meta_path, "r") as f:
                data = json.load(f)
            metadata = KeyMetadata.from_dict(data)
        else:
            # Create new metadata
            metadata = KeyMetadata(
                algorithm=self.algorithm,
                created_at=datetime.now(),
                key_id="imported-" + self._generate_key_id(),
                fingerprint=self._compute_fingerprint(public_key),
                description=description or f"Imported from {input_path.name}",
            )

        # Save to imported keys directory
        imported_dir = self.key_dir / "imported"
        imported_dir.mkdir(parents=True, exist_ok=True)

        key_path = imported_dir / f"{metadata.key_id}.key"
        meta_path = imported_dir / f"{metadata.key_id}.json"

        key_path.write_bytes(public_key)
        with open(meta_path, "w") as f:
            json.dump(metadata.to_dict(), f, indent=2)

        return public_key

    def check_key_health(self) -> Dict[str, Any]:
        """Check the health of the current keys.

        Returns:
            Dictionary with health check results
        """
        result = {
            "exists": False,
            "valid": False,
            "expired": False,
            "expires_soon": False,
            "days_until_expiry": None,
            "algorithm": None,
            "fingerprint": None,
            "warnings": [],
        }

        if not self._keys_exist():
            result["warnings"].append("No keys found")
            return result

        result["exists"] = True

        try:
            metadata = self.load_metadata()
            if metadata:
                result["algorithm"] = metadata.algorithm
                result["fingerprint"] = metadata.fingerprint

                if metadata.is_expired():
                    result["expired"] = True
                    result["warnings"].append("Key has expired")
                elif metadata.expires_at:
                    days_left = (metadata.expires_at - datetime.now()).days
                    result["days_until_expiry"] = days_left
                    if days_left < 30:
                        result["expires_soon"] = True
                        result["warnings"].append(
                            f"Key expires in {days_left} days"
                        )

            # Verify we can load both keys
            self.load_public_key()
            self.load_private_key()
            result["valid"] = True

        except Exception as e:
            result["warnings"].append(f"Error checking keys: {e}")

        return result

    def delete_keys(self, confirm: bool = False) -> bool:
        """Delete current keys.

        Args:
            confirm: Must be True to actually delete

        Returns:
            True if keys were deleted
        """
        if not confirm:
            raise ValueError("Must set confirm=True to delete keys")

        if not self._keys_exist():
            return False

        # Backup before deleting
        metadata = self.load_metadata()
        if metadata:
            self._backup_keys(metadata.key_id)

        # Delete files
        for filename in [self.public_key_file, self.private_key_file, self.metadata_file]:
            path = self.key_dir / filename
            if path.exists():
                path.unlink()

        return True
