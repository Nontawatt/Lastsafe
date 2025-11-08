# lastsafe – Secure file transfer with post-quantum cryptography

`lastsafe` is a command line tool for secure file transfer using **Post-Quantum Cryptography (PQC)**. It provides both **direct peer-to-peer file transfer** and optional cloud storage integration via [rclone](https://rclone.org/).

## Key Features

- **Post-Quantum Security**: Uses ML-KEM (CRYSTALS-Kyber) standardized by NIST as FIPS 203
- **Direct Peer-to-Peer Transfer**: Send files directly between computers without cloud storage
- **End-to-End Encryption**: Files are encrypted before transmission using AES-GCM
- **Cloud Integration**: Optional rclone support for encrypted cloud backups
- **Simple CLI**: Easy-to-use command line interface
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Why Post-Quantum Encryption?

Traditional public-key algorithms (RSA and elliptic curves) are expected to be broken by sufficiently powerful quantum computers. To prepare for this future, Lastsafe uses **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism), derived from the CRYSTALS-Kyber algorithm selected for standardization by NIST.

> **Disclaimer**: This tool uses liboqs which is designed for prototyping and evaluating quantum-resistant cryptography. While ML-KEM is a NIST standard, the security of post-quantum algorithms may evolve. For production deployments, consider combining with traditional algorithms (hybrid cryptography).

## Installation

### 1. Install Python Dependencies

You need Python 3.8 or newer.

```bash
pip install -r requirements.txt
```

This installs:
- `liboqs-python`: Post-quantum cryptography library
- `cryptography`: For AES-GCM symmetric encryption

### 2. Install rclone (Optional)

Only needed if you want cloud storage integration. Skip this if you only need peer-to-peer transfer.

**Linux/macOS/BSD:**
```bash
sudo -v ; curl https://rclone.org/install.sh | sudo bash
```

**macOS (Homebrew):**
```bash
brew install rclone
```

**Windows:**
Download from [rclone.org/downloads](https://rclone.org/downloads/)

After installation, configure your cloud storage:
```bash
rclone config
```

## Quick Start

### 1. Generate Keys

Both sender and receiver need keypairs:

```bash
./lastsafe.py generate-keys
```

This creates `keys/public.key` and `keys/private.key`.

**Important**: Share your public key with others, but keep your private key secret!

### 2. Direct File Transfer (Peer-to-Peer)

**Receiver's machine:**
```bash
./lastsafe.py receive --port 5555 --out received_files/
```

**Sender's machine:**
```bash
./lastsafe.py send document.pdf 192.168.1.100 \
    --port 5555 \
    --recipient-key /path/to/receiver_public.key
```

That's it! The file is encrypted with post-quantum cryptography and sent directly.

### 3. Send Entire Directory

```bash
# Receiver
./lastsafe.py receive --port 5555 --out received_files/

# Sender
./lastsafe.py send my_project/ 192.168.1.100 \
    --port 5555 \
    --recipient-key /path/to/receiver_public.key
```

## Usage Examples

### Local Encryption/Decryption

**Encrypt a file:**
```bash
./lastsafe.py encrypt secret.txt secret.txt.enc
```

**Decrypt a file:**
```bash
./lastsafe.py decrypt secret.txt.enc decrypted.txt
```

**Encrypt a directory:**
```bash
./lastsafe.py encrypt my_documents/ encrypted_documents/
```

**Decrypt a directory:**
```bash
./lastsafe.py decrypt encrypted_documents/ restored_documents/
```

### Cloud Storage (with rclone)

**Encrypt and upload to cloud:**
```bash
./lastsafe.py encrypt-upload my_documents/ gdrive:backup
```

**Download and decrypt from cloud:**
```bash
./lastsafe.py download-decrypt gdrive:backup restored_documents/
```

## How It Works

### Encryption Process

1. **Key Encapsulation**: Uses ML-KEM to generate a random shared secret for the recipient's public key, producing a small ciphertext
2. **Symmetric Encryption**: Uses the first 32 bytes of the shared secret as an AES-256 key
3. **Authenticated Encryption**: Encrypts file contents with AES-GCM (provides both confidentiality and authenticity)
4. **Packaging**: Output file contains:
   - KEM ciphertext length (4 bytes)
   - KEM ciphertext
   - AES nonce (12 bytes)
   - AES-GCM encrypted data + authentication tag

### Direct Transfer Protocol

For peer-to-peer transfers, Lastsafe:
1. Encrypts files using recipient's public key
2. Establishes TCP connection between sender and receiver
3. Sends encrypted file data with metadata
4. Receiver decrypts using their private key

All encryption happens before network transmission, ensuring end-to-end security.

## Command Reference

### Generate Keys
```bash
lastsafe.py generate-keys [--out DIR] [--alg ALGORITHM]
```

### Encrypt Files
```bash
lastsafe.py encrypt <source> <destination> [--key-dir DIR] [--alg ALGORITHM]
```

### Decrypt Files
```bash
lastsafe.py decrypt <source> <destination> [--key-dir DIR] [--alg ALGORITHM]
```

### Send Files (Peer-to-Peer)
```bash
lastsafe.py send <source> <host> --recipient-key <public_key> [--port PORT] [--alg ALGORITHM]
```

### Receive Files (Peer-to-Peer)
```bash
lastsafe.py receive [--port PORT] [--out DIR] [--key-dir DIR] [--alg ALGORITHM]
```

### Cloud Upload (rclone)
```bash
lastsafe.py encrypt-upload <source> <remote> [--key-dir DIR] [--alg ALGORITHM]
```

### Cloud Download (rclone)
```bash
lastsafe.py download-decrypt <remote> <destination> [--key-dir DIR] [--alg ALGORITHM]
```

## Available Algorithms

Lastsafe supports multiple ML-KEM variants:

- **ML-KEM-512** (default): NIST security level 1, fastest
- **ML-KEM-768**: NIST security level 3, recommended for most use cases
- **ML-KEM-1024**: NIST security level 5, maximum security

Example with stronger algorithm:
```bash
./lastsafe.py generate-keys --alg ML-KEM-768
./lastsafe.py send file.txt 192.168.1.100 --recipient-key key.pub --alg ML-KEM-768
```

## Security Considerations

### What Lastsafe Provides

✅ **Post-quantum secure encryption**: Resistant to attacks by quantum computers
✅ **End-to-end encryption**: Files encrypted before leaving your machine
✅ **Authenticated encryption**: AES-GCM prevents tampering
✅ **Forward secrecy**: Each file encrypted with unique session key

### Security Best Practices

1. **Protect your private key**: Store `private.key` securely, never share it
2. **Verify public keys**: Confirm public keys through a trusted channel
3. **Use secure networks**: For internet transfers, consider using a VPN
4. **Regular key rotation**: Generate new keypairs periodically
5. **Secure key exchange**: Use secure methods to share public keys initially

### Limitations

⚠️ **Proof of concept**: This is a demonstration tool, not audited for production
⚠️ **No perfect forward secrecy**: Same keys used for multiple sessions
⚠️ **No authentication**: Doesn't verify sender identity (only encrypts)
⚠️ **Metadata visible**: File sizes and transfer times are not hidden

For production use, consider additional security layers and professional security audit.

## Network Configuration

For peer-to-peer transfers across networks:

**Linux (UFW):**
```bash
sudo ufw allow 5555/tcp
```

**Linux (firewalld):**
```bash
sudo firewall-cmd --add-port=5555/tcp --permanent
sudo firewall-cmd --reload
```

**Windows:**
Add inbound rule for port 5555 in Windows Firewall

## Troubleshooting

### Import errors
```bash
pip install --upgrade liboqs-python cryptography
```

### Connection refused
- Check firewall settings
- Verify receiver is listening on correct port
- Confirm IP address and port number

### rclone not found
- Install rclone or use direct transfer instead
- Verify rclone is in your PATH: `which rclone`

### Key file errors
- Ensure keys are generated: `./lastsafe.py generate-keys`
- Check file permissions on key files
- Verify correct path to recipient's public key

## Performance

Approximate speeds on modern hardware:
- **Encryption**: ~100-500 MB/s (depends on file size)
- **Network transfer**: Limited by network bandwidth
- **ML-KEM operations**: ~1-5ms per file (keypair generation and encapsulation)

For large files, network bandwidth is typically the bottleneck, not cryptography.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests if applicable
4. Submit a pull request

## License

This project is released under the MIT License. See LICENSE file for details.

It depends on:
- **liboqs-python**: MIT License
- **cryptography**: Apache License 2.0 / BSD License

## References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [Open Quantum Safe](https://openquantumsafe.org/)
- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
- [rclone Documentation](https://rclone.org/docs/)

## Acknowledgments

Built using:
- **liboqs**: Post-quantum cryptography library by Open Quantum Safe
- **CRYSTALS-Kyber**: ML-KEM algorithm developers
- **cryptography.io**: Python cryptography library
- **rclone**: Cloud storage sync tool

---

**⚠️ Research Tool**: This is a demonstration of post-quantum cryptography. For production use, conduct thorough security review and consider professional cryptographic solutions.
