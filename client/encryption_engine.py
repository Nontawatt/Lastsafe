"""
Encryption Engine for Lastsafe Client
======================================

Core encryption functionality including:
- Post-Quantum Key Encapsulation (ML-KEM)
- AES-256-GCM Symmetric Encryption
- Streaming encryption for large files
- File header format handling
"""

import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Optional, Tuple
import hashlib
import hmac

try:
    import oqs
except ImportError:
    raise ImportError(
        "The 'oqs' module is required. Install with: pip install liboqs-python"
    )

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    raise ImportError(
        "The 'cryptography' module is required. Install with: pip install cryptography"
    )


# File format version for future compatibility
FILE_FORMAT_VERSION = 2

# Header structure:
# [1 byte: version]
# [1 byte: algorithm ID]
# [4 bytes: KEM ciphertext length (big-endian)]
# [N bytes: KEM ciphertext]
# [12 bytes: AES nonce]
# [16 bytes: file checksum (HMAC-SHA256 truncated)]
# [remaining: AES-GCM encrypted payload]

ALGORITHM_IDS = {
    "ML-KEM-512": 1,
    "ML-KEM-768": 2,
    "ML-KEM-1024": 3,
}

ALGORITHM_NAMES = {v: k for k, v in ALGORITHM_IDS.items()}


@dataclass
class EncryptionResult:
    """Result of an encryption operation."""
    success: bool
    output_path: Optional[Path] = None
    bytes_processed: int = 0
    checksum: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DecryptionResult:
    """Result of a decryption operation."""
    success: bool
    output_path: Optional[Path] = None
    bytes_processed: int = 0
    checksum_verified: bool = False
    error: Optional[str] = None


class EncryptionEngine:
    """Core encryption engine using Post-Quantum cryptography.

    This engine provides:
    - ML-KEM (CRYSTALS-Kyber) for key encapsulation
    - AES-256-GCM for symmetric encryption
    - HKDF for proper key derivation
    - Streaming support for large files
    """

    def __init__(
        self,
        kem_algorithm: str = "ML-KEM-512",
        chunk_size: int = 64 * 1024 * 1024,  # 64MB default
    ):
        """Initialize the encryption engine.

        Args:
            kem_algorithm: Post-quantum KEM algorithm to use
            chunk_size: Size of chunks for streaming encryption
        """
        if kem_algorithm not in ALGORITHM_IDS:
            raise ValueError(
                f"Unsupported algorithm: {kem_algorithm}. "
                f"Supported: {list(ALGORITHM_IDS.keys())}"
            )
        self.kem_algorithm = kem_algorithm
        self.chunk_size = chunk_size

    def _derive_keys(
        self, shared_secret: bytes, nonce: bytes
    ) -> Tuple[bytes, bytes]:
        """Derive AES key and HMAC key from shared secret using HKDF.

        Args:
            shared_secret: Raw shared secret from KEM
            nonce: Random nonce for key derivation

        Returns:
            Tuple of (aes_key, hmac_key) each 32 bytes
        """
        # Use HKDF to derive keys properly
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for AES + 32 bytes for HMAC
            salt=nonce,
            info=b"lastsafe-v2-encryption",
        )
        derived = hkdf.derive(shared_secret)
        return derived[:32], derived[32:]

    def _compute_checksum(self, data: bytes, hmac_key: bytes) -> bytes:
        """Compute HMAC-SHA256 checksum truncated to 16 bytes.

        Args:
            data: Data to checksum
            hmac_key: HMAC key

        Returns:
            16-byte truncated HMAC
        """
        return hmac.new(hmac_key, data, hashlib.sha256).digest()[:16]

    def encrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        public_key: bytes,
        use_streaming: bool = False,
    ) -> EncryptionResult:
        """Encrypt a single file using PQC KEM and AES-GCM.

        Args:
            input_path: Path to plaintext file
            output_path: Path for encrypted output
            public_key: Recipient's public key bytes
            use_streaming: Use streaming for large files

        Returns:
            EncryptionResult with operation details
        """
        try:
            file_size = input_path.stat().st_size

            # Use streaming for large files
            if use_streaming and file_size > self.chunk_size:
                return self._encrypt_file_streaming(
                    input_path, output_path, public_key
                )

            # Read entire file for small files
            plaintext = input_path.read_bytes()

            # Perform KEM encapsulation
            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            # Generate nonce
            nonce = secrets.token_bytes(12)

            # Derive keys
            aes_key, hmac_key = self._derive_keys(shared_secret, nonce)

            # Compute checksum of plaintext
            checksum = self._compute_checksum(plaintext, hmac_key)

            # Encrypt with AES-GCM
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Build header and write file
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with output_path.open("wb") as f:
                # Write header
                f.write(struct.pack("B", FILE_FORMAT_VERSION))
                f.write(struct.pack("B", ALGORITHM_IDS[self.kem_algorithm]))
                f.write(struct.pack("!I", len(kem_ciphertext)))
                f.write(kem_ciphertext)
                f.write(nonce)
                f.write(checksum)
                f.write(ciphertext)

            return EncryptionResult(
                success=True,
                output_path=output_path,
                bytes_processed=len(plaintext),
                checksum=checksum.hex(),
            )

        except Exception as e:
            return EncryptionResult(
                success=False,
                error=str(e),
            )

    def _encrypt_file_streaming(
        self,
        input_path: Path,
        output_path: Path,
        public_key: bytes,
    ) -> EncryptionResult:
        """Encrypt a large file using streaming.

        For very large files, we encrypt in chunks, each with its own
        nonce derived from the base nonce + counter.

        Args:
            input_path: Path to plaintext file
            output_path: Path for encrypted output
            public_key: Recipient's public key bytes

        Returns:
            EncryptionResult with operation details
        """
        try:
            # Perform KEM encapsulation
            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                kem_ciphertext, shared_secret = kem.encap_secret(public_key)

            # Generate base nonce
            base_nonce = secrets.token_bytes(8)
            full_nonce = base_nonce + struct.pack("!I", 0)

            # Derive keys
            aes_key, hmac_key = self._derive_keys(shared_secret, full_nonce)
            aesgcm = AESGCM(aes_key)

            # Prepare output
            output_path.parent.mkdir(parents=True, exist_ok=True)
            total_bytes = 0
            chunk_count = 0

            # Create HMAC context for streaming checksum
            hmac_ctx = hmac.new(hmac_key, digestmod=hashlib.sha256)

            with input_path.open("rb") as fin, output_path.open("wb") as fout:
                # Write header (reserve space for final checksum)
                fout.write(struct.pack("B", FILE_FORMAT_VERSION))
                fout.write(struct.pack("B", ALGORITHM_IDS[self.kem_algorithm] | 0x80))  # Streaming flag
                fout.write(struct.pack("!I", len(kem_ciphertext)))
                fout.write(kem_ciphertext)
                fout.write(base_nonce)  # 8 bytes for streaming mode
                checksum_pos = fout.tell()
                fout.write(b"\x00" * 16)  # Placeholder for checksum

                # Write chunk count placeholder
                chunk_count_pos = fout.tell()
                fout.write(struct.pack("!I", 0))

                # Encrypt chunks
                while True:
                    chunk = fin.read(self.chunk_size)
                    if not chunk:
                        break

                    # Update HMAC
                    hmac_ctx.update(chunk)

                    # Create chunk nonce
                    chunk_nonce = base_nonce + struct.pack("!I", chunk_count)

                    # Encrypt chunk
                    encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)

                    # Write chunk length and data
                    fout.write(struct.pack("!I", len(encrypted_chunk)))
                    fout.write(encrypted_chunk)

                    total_bytes += len(chunk)
                    chunk_count += 1

                # Finalize checksum
                checksum = hmac_ctx.digest()[:16]

                # Write final checksum
                fout.seek(checksum_pos)
                fout.write(checksum)

                # Write chunk count
                fout.seek(chunk_count_pos)
                fout.write(struct.pack("!I", chunk_count))

            return EncryptionResult(
                success=True,
                output_path=output_path,
                bytes_processed=total_bytes,
                checksum=checksum.hex(),
            )

        except Exception as e:
            return EncryptionResult(
                success=False,
                error=str(e),
            )

    def decrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        secret_key: bytes,
    ) -> DecryptionResult:
        """Decrypt a file encrypted by this engine.

        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            secret_key: Private key bytes

        Returns:
            DecryptionResult with operation details
        """
        try:
            with input_path.open("rb") as f:
                # Read header
                version = struct.unpack("B", f.read(1))[0]
                if version != FILE_FORMAT_VERSION:
                    # Try legacy format
                    if version > 10:  # Likely legacy format (first byte is length MSB)
                        f.seek(0)
                        return self._decrypt_legacy_file(input_path, output_path, secret_key)
                    raise ValueError(f"Unsupported file format version: {version}")

                alg_byte = struct.unpack("B", f.read(1))[0]
                is_streaming = (alg_byte & 0x80) != 0
                alg_id = alg_byte & 0x7F

                if alg_id not in ALGORITHM_NAMES:
                    raise ValueError(f"Unknown algorithm ID: {alg_id}")

                kem_algorithm = ALGORITHM_NAMES[alg_id]

                # Read KEM ciphertext
                kem_ct_len = struct.unpack("!I", f.read(4))[0]
                kem_ciphertext = f.read(kem_ct_len)

                if is_streaming:
                    return self._decrypt_file_streaming(
                        f, output_path, secret_key, kem_algorithm, kem_ciphertext
                    )

                # Read nonce and checksum
                nonce = f.read(12)
                stored_checksum = f.read(16)
                ciphertext = f.read()

            # Perform KEM decapsulation
            with oqs.KeyEncapsulation(kem_algorithm, secret_key) as kem:
                shared_secret = kem.decap_secret(kem_ciphertext)

            # Derive keys
            aes_key, hmac_key = self._derive_keys(shared_secret, nonce)

            # Decrypt
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            # Verify checksum
            computed_checksum = self._compute_checksum(plaintext, hmac_key)
            checksum_verified = hmac.compare_digest(stored_checksum, computed_checksum)

            # Write output
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(plaintext)

            return DecryptionResult(
                success=True,
                output_path=output_path,
                bytes_processed=len(plaintext),
                checksum_verified=checksum_verified,
            )

        except Exception as e:
            return DecryptionResult(
                success=False,
                error=str(e),
            )

    def _decrypt_file_streaming(
        self,
        f: BinaryIO,
        output_path: Path,
        secret_key: bytes,
        kem_algorithm: str,
        kem_ciphertext: bytes,
    ) -> DecryptionResult:
        """Decrypt a streaming-encrypted file.

        Args:
            f: File handle positioned after KEM ciphertext
            output_path: Path for decrypted output
            secret_key: Private key bytes
            kem_algorithm: KEM algorithm name
            kem_ciphertext: KEM ciphertext bytes

        Returns:
            DecryptionResult with operation details
        """
        # Read base nonce and checksum
        base_nonce = f.read(8)
        stored_checksum = f.read(16)
        chunk_count = struct.unpack("!I", f.read(4))[0]

        # Perform KEM decapsulation
        full_nonce = base_nonce + struct.pack("!I", 0)
        with oqs.KeyEncapsulation(kem_algorithm, secret_key) as kem:
            shared_secret = kem.decap_secret(kem_ciphertext)

        # Derive keys
        aes_key, hmac_key = self._derive_keys(shared_secret, full_nonce)
        aesgcm = AESGCM(aes_key)

        # Create HMAC context
        hmac_ctx = hmac.new(hmac_key, digestmod=hashlib.sha256)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        total_bytes = 0

        with output_path.open("wb") as fout:
            for i in range(chunk_count):
                # Read chunk length and data
                chunk_len = struct.unpack("!I", f.read(4))[0]
                encrypted_chunk = f.read(chunk_len)

                # Create chunk nonce
                chunk_nonce = base_nonce + struct.pack("!I", i)

                # Decrypt chunk
                plaintext_chunk = aesgcm.decrypt(chunk_nonce, encrypted_chunk, None)

                # Update HMAC
                hmac_ctx.update(plaintext_chunk)

                # Write chunk
                fout.write(plaintext_chunk)
                total_bytes += len(plaintext_chunk)

        # Verify checksum
        computed_checksum = hmac_ctx.digest()[:16]
        checksum_verified = hmac.compare_digest(stored_checksum, computed_checksum)

        return DecryptionResult(
            success=True,
            output_path=output_path,
            bytes_processed=total_bytes,
            checksum_verified=checksum_verified,
        )

    def _decrypt_legacy_file(
        self,
        input_path: Path,
        output_path: Path,
        secret_key: bytes,
    ) -> DecryptionResult:
        """Decrypt a file in the legacy format (v1).

        Legacy format:
        [uint32: KEM ciphertext length]
        [KEM ciphertext]
        [12-byte nonce]
        [AES-GCM encrypted data]

        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            secret_key: Private key bytes

        Returns:
            DecryptionResult with operation details
        """
        with input_path.open("rb") as f:
            # Read header
            header = f.read(4)
            if len(header) != 4:
                raise ValueError("File too short")
            kem_ct_len = struct.unpack("!I", header)[0]
            kem_ciphertext = f.read(kem_ct_len)
            nonce = f.read(12)
            ciphertext = f.read()

        # Decapsulate (assume ML-KEM-512 for legacy files)
        with oqs.KeyEncapsulation(self.kem_algorithm, secret_key) as kem:
            shared_secret = kem.decap_secret(kem_ciphertext)

        # Derive key (legacy: simple slice)
        if len(shared_secret) < 32:
            raise ValueError("Shared secret too short")
        aes_key = shared_secret[:32]

        # Decrypt
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # Write output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(plaintext)

        return DecryptionResult(
            success=True,
            output_path=output_path,
            bytes_processed=len(plaintext),
            checksum_verified=False,  # No checksum in legacy format
        )

    def encrypt_bytes(
        self, data: bytes, public_key: bytes
    ) -> Tuple[bytes, str]:
        """Encrypt raw bytes in memory.

        Args:
            data: Plaintext bytes to encrypt
            public_key: Recipient's public key

        Returns:
            Tuple of (encrypted_bytes, checksum_hex)
        """
        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(public_key)

        nonce = secrets.token_bytes(12)
        aes_key, hmac_key = self._derive_keys(shared_secret, nonce)
        checksum = self._compute_checksum(data, hmac_key)

        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Build result
        result = bytearray()
        result.append(FILE_FORMAT_VERSION)
        result.append(ALGORITHM_IDS[self.kem_algorithm])
        result.extend(struct.pack("!I", len(kem_ciphertext)))
        result.extend(kem_ciphertext)
        result.extend(nonce)
        result.extend(checksum)
        result.extend(ciphertext)

        return bytes(result), checksum.hex()

    def decrypt_bytes(self, data: bytes, secret_key: bytes) -> bytes:
        """Decrypt raw bytes in memory.

        Args:
            data: Encrypted bytes
            secret_key: Private key bytes

        Returns:
            Decrypted plaintext bytes
        """
        offset = 0

        version = struct.unpack("B", data[offset:offset+1])[0]
        offset += 1

        if version != FILE_FORMAT_VERSION:
            # Try legacy format
            return self._decrypt_legacy_bytes(data, secret_key)

        alg_id = struct.unpack("B", data[offset:offset+1])[0] & 0x7F
        offset += 1

        kem_ct_len = struct.unpack("!I", data[offset:offset+4])[0]
        offset += 4

        kem_ciphertext = data[offset:offset+kem_ct_len]
        offset += kem_ct_len

        nonce = data[offset:offset+12]
        offset += 12

        stored_checksum = data[offset:offset+16]
        offset += 16

        ciphertext = data[offset:]

        kem_algorithm = ALGORITHM_NAMES[alg_id]
        with oqs.KeyEncapsulation(kem_algorithm, secret_key) as kem:
            shared_secret = kem.decap_secret(kem_ciphertext)

        aes_key, hmac_key = self._derive_keys(shared_secret, nonce)
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # Verify checksum
        computed_checksum = self._compute_checksum(plaintext, hmac_key)
        if not hmac.compare_digest(stored_checksum, computed_checksum):
            raise ValueError("Checksum verification failed")

        return plaintext

    def _decrypt_legacy_bytes(self, data: bytes, secret_key: bytes) -> bytes:
        """Decrypt legacy format bytes."""
        kem_ct_len = struct.unpack("!I", data[0:4])[0]
        kem_ciphertext = data[4:4+kem_ct_len]
        nonce = data[4+kem_ct_len:4+kem_ct_len+12]
        ciphertext = data[4+kem_ct_len+12:]

        with oqs.KeyEncapsulation(self.kem_algorithm, secret_key) as kem:
            shared_secret = kem.decap_secret(kem_ciphertext)

        aes_key = shared_secret[:32]
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
