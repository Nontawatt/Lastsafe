#!/usr/bin/env python3
"""
Lastsafe Client CLI
====================

Command-line interface for the Lastsafe encrypted cloud storage client.

Usage:
    lastsafe-client generate-keys [--key-dir DIR] [--algorithm ALG]
    lastsafe-client encrypt SOURCE DEST [--key-dir DIR]
    lastsafe-client decrypt SOURCE DEST [--key-dir DIR]
    lastsafe-client upload SOURCE REMOTE [--provider PROVIDER]
    lastsafe-client download REMOTE DEST [--provider PROVIDER]
    lastsafe-client list REMOTE [--provider PROVIDER] [--recursive]
    lastsafe-client keys --check | --rotate | --export FILE
"""

import argparse
import sys
from pathlib import Path
from typing import Optional


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="lastsafe-client",
        description="Lastsafe - Post-Quantum Encrypted Cloud Storage Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate new keys
  lastsafe-client generate-keys --key-dir ~/.lastsafe/keys

  # Encrypt and upload to S3
  lastsafe-client upload ./data s3://my-bucket/backup --provider s3

  # Download and decrypt from S3
  lastsafe-client download s3://my-bucket/backup ./restored --provider s3

  # Encrypt and upload using rclone
  lastsafe-client upload ./data gdrive:backup --provider rclone

  # Check key status
  lastsafe-client keys --check

Cloud Providers:
  s3, aws       - Amazon S3 (requires boto3)
  gcs, google   - Google Cloud Storage (requires google-cloud-storage)
  azure         - Azure Blob Storage (requires azure-storage-blob)
  rclone        - Any rclone-supported backend (requires rclone)
        """,
    )

    # Global options
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--key-dir",
        type=Path,
        help="Directory containing keys (default: ~/.lastsafe/keys)",
    )
    parser.add_argument(
        "--algorithm",
        "--alg",
        default="ML-KEM-512",
        help="KEM algorithm (default: ML-KEM-512)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress output except errors",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-keys command
    parser_keys_gen = subparsers.add_parser(
        "generate-keys",
        help="Generate a new PQC keypair",
    )
    parser_keys_gen.add_argument(
        "--description",
        help="Description for the keys",
    )
    parser_keys_gen.add_argument(
        "--expires",
        type=int,
        help="Days until key expires",
    )

    # encrypt command
    parser_enc = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file or directory locally",
    )
    parser_enc.add_argument(
        "source",
        type=Path,
        help="Source file or directory to encrypt",
    )
    parser_enc.add_argument(
        "destination",
        type=Path,
        help="Destination path for encrypted output",
    )
    parser_enc.add_argument(
        "--streaming",
        action="store_true",
        help="Force streaming encryption for large files",
    )

    # decrypt command
    parser_dec = subparsers.add_parser(
        "decrypt",
        help="Decrypt a file or directory locally",
    )
    parser_dec.add_argument(
        "source",
        type=Path,
        help="Encrypted file or directory to decrypt",
    )
    parser_dec.add_argument(
        "destination",
        type=Path,
        help="Destination path for decrypted output",
    )

    # upload command
    parser_up = subparsers.add_parser(
        "upload",
        help="Encrypt and upload to cloud storage",
    )
    parser_up.add_argument(
        "source",
        type=Path,
        help="Local file or directory to upload",
    )
    parser_up.add_argument(
        "remote",
        help="Remote destination (e.g., s3://bucket/path, gdrive:folder)",
    )
    parser_up.add_argument(
        "--provider", "-p",
        default="rclone",
        help="Cloud provider (s3, gcs, azure, rclone)",
    )
    parser_up.add_argument(
        "--bucket",
        help="Bucket/container name (for s3/gcs/azure)",
    )
    parser_up.add_argument(
        "--region",
        help="Region (for s3)",
    )

    # download command
    parser_down = subparsers.add_parser(
        "download",
        help="Download from cloud storage and decrypt",
    )
    parser_down.add_argument(
        "remote",
        help="Remote source (e.g., s3://bucket/path, gdrive:folder)",
    )
    parser_down.add_argument(
        "destination",
        type=Path,
        help="Local destination path",
    )
    parser_down.add_argument(
        "--provider", "-p",
        default="rclone",
        help="Cloud provider (s3, gcs, azure, rclone)",
    )
    parser_down.add_argument(
        "--bucket",
        help="Bucket/container name (for s3/gcs/azure)",
    )

    # list command
    parser_list = subparsers.add_parser(
        "list",
        help="List files in remote storage",
    )
    parser_list.add_argument(
        "remote",
        help="Remote path to list",
    )
    parser_list.add_argument(
        "--provider", "-p",
        default="rclone",
        help="Cloud provider",
    )
    parser_list.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="List recursively",
    )

    # keys command
    parser_keys = subparsers.add_parser(
        "keys",
        help="Key management operations",
    )
    keys_group = parser_keys.add_mutually_exclusive_group(required=True)
    keys_group.add_argument(
        "--check",
        action="store_true",
        help="Check key health and status",
    )
    keys_group.add_argument(
        "--rotate",
        action="store_true",
        help="Rotate keys (backup old, generate new)",
    )
    keys_group.add_argument(
        "--export",
        type=Path,
        metavar="FILE",
        help="Export public key to file",
    )
    keys_group.add_argument(
        "--list-backups",
        action="store_true",
        help="List available key backups",
    )

    # init command
    parser_init = subparsers.add_parser(
        "init",
        help="Initialize configuration and keys",
    )
    parser_init.add_argument(
        "--provider",
        default="rclone",
        help="Default cloud provider",
    )

    return parser


def progress_bar(current: int, total: int, filename: str = "") -> None:
    """Display a progress bar."""
    if total == 0:
        return

    width = 40
    percent = current / total
    filled = int(width * percent)
    bar = "=" * filled + "-" * (width - filled)
    name = filename[:30] if filename else ""

    sys.stdout.write(f"\r[{bar}] {percent*100:.1f}% {name}")
    sys.stdout.flush()

    if current >= total:
        sys.stdout.write("\n")


def run_generate_keys(args, client) -> int:
    """Handle generate-keys command."""
    try:
        keypair = client.generate_keys(
            description=args.description if hasattr(args, 'description') else None,
            expires_in_days=args.expires if hasattr(args, 'expires') else None,
        )
        print(f"Keys generated successfully!")
        print(f"  Key ID: {keypair.metadata.key_id}")
        print(f"  Algorithm: {keypair.metadata.algorithm}")
        print(f"  Fingerprint: {keypair.metadata.fingerprint}")
        if keypair.metadata.expires_at:
            print(f"  Expires: {keypair.metadata.expires_at.strftime('%Y-%m-%d')}")
        return 0
    except FileExistsError as e:
        print(f"Error: {e}")
        print("Use 'lastsafe-client keys --rotate' to generate new keys.")
        return 1
    except Exception as e:
        print(f"Error generating keys: {e}")
        return 1


def run_encrypt(args, client) -> int:
    """Handle encrypt command."""
    try:
        use_streaming = getattr(args, 'streaming', None)
        result = client.encrypt(args.source, args.destination, use_streaming)
        if result.success:
            print(f"Encryption complete: {args.destination}")
            print(f"  Bytes processed: {result.bytes_processed:,}")
            return 0
        else:
            print(f"Encryption failed: {result.error}")
            return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def run_decrypt(args, client) -> int:
    """Handle decrypt command."""
    try:
        result = client.decrypt(args.source, args.destination)
        if result.success:
            print(f"Decryption complete: {args.destination}")
            print(f"  Bytes processed: {result.bytes_processed:,}")
            return 0
        else:
            print(f"Decryption failed: {result.error}")
            return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def run_upload(args, client) -> int:
    """Handle upload command."""
    try:
        provider_kwargs = {}
        if hasattr(args, 'bucket') and args.bucket:
            provider_kwargs['bucket'] = args.bucket
        if hasattr(args, 'region') and args.region:
            provider_kwargs['region'] = args.region

        callback = progress_bar if not getattr(args, 'quiet', False) else None

        result = client.encrypt_upload(
            args.source,
            args.remote,
            provider=args.provider,
            progress_callback=callback,
            **provider_kwargs,
        )

        if result.success:
            print(f"\nUpload complete: {args.remote}")
            print(f"  Files: {result.files_processed}")
            print(f"  Bytes: {result.bytes_processed:,}")
            return 0
        else:
            print(f"\nUpload failed:")
            for error in result.errors:
                print(f"  - {error}")
            return 1
    except Exception as e:
        print(f"\nError: {e}")
        return 1


def run_download(args, client) -> int:
    """Handle download command."""
    try:
        provider_kwargs = {}
        if hasattr(args, 'bucket') and args.bucket:
            provider_kwargs['bucket'] = args.bucket

        callback = progress_bar if not getattr(args, 'quiet', False) else None

        result = client.download_decrypt(
            args.remote,
            args.destination,
            provider=args.provider,
            progress_callback=callback,
            **provider_kwargs,
        )

        if result.success:
            print(f"\nDownload complete: {args.destination}")
            print(f"  Files: {result.files_processed}")
            print(f"  Bytes: {result.bytes_processed:,}")
            return 0
        else:
            print(f"\nDownload failed:")
            for error in result.errors:
                print(f"  - {error}")
            return 1
    except Exception as e:
        print(f"\nError: {e}")
        return 1


def run_list(args, client) -> int:
    """Handle list command."""
    try:
        files = list(client.list_remote(
            args.remote,
            provider=args.provider,
            recursive=args.recursive,
        ))

        if not files:
            print("No files found.")
            return 0

        for f in files:
            type_indicator = "D" if f.is_directory else "F"
            size = f"{f.size:>10,}" if not f.is_directory else " " * 10
            print(f"[{type_indicator}] {size}  {f.path}")

        print(f"\nTotal: {len(files)} items")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


def run_keys(args, client) -> int:
    """Handle keys command."""
    try:
        if args.check:
            health = client.check_keys()
            print("Key Status:")
            print(f"  Exists: {health['exists']}")
            print(f"  Valid: {health['valid']}")
            if health.get('algorithm'):
                print(f"  Algorithm: {health['algorithm']}")
            if health.get('fingerprint'):
                print(f"  Fingerprint: {health['fingerprint']}")
            if health.get('days_until_expiry') is not None:
                print(f"  Days until expiry: {health['days_until_expiry']}")
            if health.get('expired'):
                print("  WARNING: Key has expired!")
            if health.get('expires_soon'):
                print("  WARNING: Key expires soon!")
            for warning in health.get('warnings', []):
                print(f"  Warning: {warning}")
            return 0

        elif args.rotate:
            keypair = client.rotate_keys()
            print("Keys rotated successfully!")
            print(f"  New Key ID: {keypair.metadata.key_id}")
            print(f"  Fingerprint: {keypair.metadata.fingerprint}")
            return 0

        elif args.export:
            client.export_public_key(args.export)
            print(f"Public key exported to: {args.export}")
            return 0

        elif getattr(args, 'list_backups', False):
            backups = client.key_manager.list_backups()
            if not backups:
                print("No backups found.")
            else:
                print("Available backups:")
                for backup in backups:
                    print(f"  - {backup}")
            return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def run_init(args, client) -> int:
    """Handle init command."""
    try:
        # Save default configuration
        client.config.cloud.default_provider = args.provider
        client.config.save()
        print("Configuration initialized.")
        print(f"  Config file: ~/.lastsafe/config.yaml")
        print(f"  Default provider: {args.provider}")
        print("\nNext steps:")
        print("  1. Run 'lastsafe-client generate-keys' to create encryption keys")
        print("  2. Configure your cloud provider credentials")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Import here to avoid circular imports and allow --help without dependencies
    try:
        from .secure_client import SecureClient
        from .config import ClientConfig
    except ImportError:
        from secure_client import SecureClient
        from config import ClientConfig

    # Build configuration
    config = ClientConfig.load(args.config)

    # Override with command-line arguments
    if args.key_dir:
        config.keys.key_dir = args.key_dir
    if args.algorithm:
        config.encryption.kem_algorithm = args.algorithm
    if args.verbose:
        config.logging.verbose = True
        config.logging.level = "DEBUG"
    if args.quiet:
        config.logging.level = "ERROR"

    # Initialize client
    client = SecureClient(config=config)

    # Route to command handler
    handlers = {
        "generate-keys": run_generate_keys,
        "encrypt": run_encrypt,
        "decrypt": run_decrypt,
        "upload": run_upload,
        "download": run_download,
        "list": run_list,
        "keys": run_keys,
        "init": run_init,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args, client)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
