# Lastsafe Quickstart Guide

This guide will help you get started with Lastsafe for secure file transfer using Post-Quantum Cryptography.

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Make the script executable:
```bash
chmod +x lastsafe.py
```

## Quick Examples

### 1. Generate Keys

First, both sender and receiver need to generate their own keypairs:

```bash
# Generate keys (creates keys/public.key and keys/private.key)
./lastsafe.py generate-keys
```

**IMPORTANT**: Share your `public.key` with others, but keep `private.key` secret!

### 2. Direct Peer-to-Peer File Transfer (No Cloud Required!)

#### Example: Send a single file

**On Receiver's machine** (IP: 192.168.1.100):
```bash
# Start listening for incoming file
./lastsafe.py receive --port 5555 --out received_files/
```

**On Sender's machine**:
```bash
# Send file to receiver
./lastsafe.py send document.pdf 192.168.1.100 \
    --port 5555 \
    --recipient-key /path/to/receiver_public.key
```

#### Example: Send an entire directory

**On Receiver's machine**:
```bash
./lastsafe.py receive --port 5555 --out received_files/
```

**On Sender's machine**:
```bash
./lastsafe.py send my_project/ 192.168.1.100 \
    --port 5555 \
    --recipient-key /path/to/receiver_public.key
```

### 3. Encrypt/Decrypt Files Locally

#### Encrypt a file:
```bash
./lastsafe.py encrypt secret.txt secret.txt.enc
```

#### Decrypt a file:
```bash
./lastsafe.py decrypt secret.txt.enc decrypted.txt
```

#### Encrypt an entire directory:
```bash
./lastsafe.py encrypt my_documents/ encrypted_documents/
```

#### Decrypt a directory:
```bash
./lastsafe.py decrypt encrypted_documents/ restored_documents/
```

### 4. Cloud Storage with rclone (Optional)

If you have rclone configured:

#### Upload to cloud:
```bash
./lastsafe.py encrypt-upload my_documents/ gdrive:backup
```

#### Download from cloud:
```bash
./lastsafe.py download-decrypt gdrive:backup restored_documents/
```

## Complete Workflow Example

### Scenario: Alice wants to send files to Bob securely

1. **Both Alice and Bob generate keys:**
```bash
# Alice's machine
./lastsafe.py generate-keys --out alice_keys

# Bob's machine
./lastsafe.py generate-keys --out bob_keys
```

2. **Exchange public keys:**
- Alice sends `alice_keys/public.key` to Bob
- Bob sends `bob_keys/public.key` to Alice

3. **Bob starts receiving:**
```bash
./lastsafe.py receive --port 5555 --out received/ --key-dir bob_keys
```

4. **Alice sends the files:**
```bash
./lastsafe.py send confidential_report.pdf 192.168.1.50 \
    --port 5555 \
    --recipient-key bob_public.key
```

Done! The file is securely transferred with Post-Quantum encryption!

## Firewall Configuration

If you're using the peer-to-peer transfer, make sure the receiving machine's firewall allows incoming connections on the specified port (default: 5555):

```bash
# On Linux (using ufw)
sudo ufw allow 5555/tcp

# On Linux (using firewall-cmd)
sudo firewall-cmd --add-port=5555/tcp --permanent
sudo firewall-cmd --reload
```

## Security Notes

1. **Keep your private key secure**: Never share `private.key` with anyone
2. **Verify public keys**: When exchanging public keys, verify them through a secure channel
3. **Use strong algorithms**: The default ML-KEM-512 provides quantum-resistant security
4. **Network security**: For peer-to-peer transfers over the internet, consider using a VPN

## Troubleshooting

### Connection refused
- Make sure the receiver is running and listening on the correct port
- Check firewall settings on both machines
- Verify IP address and port number

### Import errors
- Make sure all dependencies are installed: `pip install -r requirements.txt`
- Try installing liboqs-python separately: `pip install liboqs-python`

### File not found errors
- Check that the recipient's public key path is correct
- Verify that your keys directory contains the necessary keys

## Advanced Usage

### Use different encryption algorithm:
```bash
# Generate keys with ML-KEM-768 (higher security)
./lastsafe.py generate-keys --alg ML-KEM-768

# Send file with specific algorithm
./lastsafe.py send file.txt 192.168.1.100 \
    --recipient-key bob_public.key \
    --alg ML-KEM-768
```

### Custom port:
```bash
# Receive on custom port
./lastsafe.py receive --port 8080

# Send to custom port
./lastsafe.py send file.txt 192.168.1.100 --port 8080 \
    --recipient-key bob_public.key
```

## Getting Help

View all available commands:
```bash
./lastsafe.py --help
```

View help for specific command:
```bash
./lastsafe.py send --help
./lastsafe.py receive --help
```
