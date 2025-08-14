# lastsafe – Secure file transfer with post‑quantum cryptography

`lastsafe` is a simple command line tool that combines the proven
functionality of [rclone](https://rclone.org/) with modern
post‑quantum encryption.  It acts as a wrapper around rclone’s
`copy` command, transparently encrypting your files before upload
and decrypting them after download.  Under the hood it uses
**ML‑KEM**, the key‑encapsulation mechanism derived from the
CRYSTALS‑Kyber algorithm that has been selected for standardisation by
NIST, together with AES‑GCM for symmetric encryption.  Keys are
generated locally and stored in simple `public.key`/`private.key` files.

## Why post‑quantum encryption?

Traditional public‑key algorithms (RSA and elliptic curves) are
expected to be broken by sufficiently powerful quantum computers.  To
prepare for this future, projects such as the Open Quantum Safe
initiative have developed **liboqs**, a library implementing
quantum‑resistant algorithms.  The Python bindings `liboqs‑python`
provide three classes for post‑quantum cryptography: `KeyEncapsulation`,
`Signature` and `StatefulSignature`【901244997312077†L422-L433】.  When using `lastsafe`
you need only the first of these classes; it allows you to generate
key pairs and perform key encapsulation and decapsulation using
algorithms such as ML‑KEM.

> **Disclaimer:** liboqs is designed for prototyping and evaluating
> quantum‑resistant cryptography【901244997312077†L475-L493】.  The security of
> proposed post‑quantum algorithms may evolve rapidly and there is
> no guarantee that today’s algorithms will remain secure against
> future classical or quantum attacks.  Consider combining post‑quantum
> algorithms with traditional algorithms (hybrid cryptography) for
> production deployments【901244997312077†L475-L493】.

## Features

- **Key generation:** generate a ML‑KEM public/secret key pair and store
  it on disk.
- **File and directory encryption:** encrypt files using the
  encapsulated symmetric key and AES‑GCM; header information
  containing the KEM ciphertext and AES nonce is prepended to each
  file.
- **Seamless upload/download:** encrypt directories and upload them
  using rclone, or download encrypted data and decrypt it locally.
- **Portable:** implemented in pure Python; runs on Linux, macOS and
  Windows.

## Installation

### 1. Install Python dependencies

You need Python 3.8 or newer.  Create a virtual environment and
install the required packages:

    python3 -m venv venv
    . venv/bin/activate
    pip install -r requirements.txt

The `oqs` package (from `liboqs‑python`) defines `KeyEncapsulation`,
`Signature` and `StatefulSignature` classes【901244997312077†L422-L433】.  Each class must
be instantiated with the name of a supported algorithm.  In this
project we use `ML‑KEM‑512` by default.  The `cryptography` package
provides the AES‑GCM implementation used to encrypt file contents.

### 2. Install rclone

`lastsafe` relies on an external `rclone` binary to perform data
transfers.  If you do not already have rclone installed, follow the
official installation instructions.  On Linux/macOS/BSD systems you
can use the provided install script【943173254188109†L79-L88】:

    sudo -v ; curl https://rclone.org/install.sh | sudo bash

Alternatively you can download a pre‑compiled binary, unpack it and
copy it into `/usr/bin/`【943173254188109†L94-L104】:

    curl -O https://downloads.rclone.org/rclone-current-linux-amd64.zip
    unzip rclone-current-linux-amd64.zip
    cd rclone-*-linux-amd64
    sudo cp rclone /usr/bin/
    sudo chown root:root /usr/bin/rclone
    sudo chmod 755 /usr/bin/rclone

On macOS you can also install rclone via Homebrew (`brew install
rclone`【943173254188109†L116-L124】), MacPorts (`sudo port install rclone`【943173254188109†L131-L136】) or by
downloading the binary directly.  Windows users should download
`rclone.exe` from the [releases page](https://rclone.org/downloads/),
extract it and run `rclone.exe config` from a command prompt【943173254188109†L189-L203】.

After installation run `rclone config` to set up your remote storage
accounts (e.g. Google Drive, S3, etc.).  Consult the [rclone
documentation](https://rclone.org/docs/) for details.

### 3. Clone this repository

Clone or download this repository and ensure `lastsafe.py` is
executable:

    git clone https://github.com/your-username/lastsafe.git
    cd lastsafe
    chmod +x lastsafe.py

## Usage

All commands are executed via `python3 lastsafe.py <command>`.  By
default keys are read from or written to the `keys/` directory
relative to the current working directory.

### 1. Generate a new key pair

    python3 lastsafe.py generate-keys --out keys

This creates `public.key` and `private.key` in the `keys/` directory.

### 2. Encrypt a file or directory

To encrypt a single file:

    python3 lastsafe.py encrypt /path/to/plain.txt /path/to/plain.txt.enc \
        --key-dir keys

To encrypt an entire directory:

    python3 lastsafe.py encrypt /path/to/plain_directory /path/to/encrypted_directory \
        --key-dir keys

### 3. Decrypt a file or directory

    python3 lastsafe.py decrypt /path/to/encrypted_file /path/to/decrypted_file \
        --key-dir keys

    python3 lastsafe.py decrypt /path/to/encrypted_directory /path/to/decrypted_directory \
        --key-dir keys

### 4. Encrypt and upload to a remote

Once you have configured a remote using `rclone config`, you can
encrypt a local directory and upload it directly:

    python3 lastsafe.py encrypt-upload /path/to/local_folder remote:backup \
        --key-dir keys

This command creates a temporary directory, encrypts every file in
`/path/to/local_folder` using your `public.key`, and then runs
`rclone copy` to upload the encrypted files to the `remote:backup`
location.  Progress information from rclone is displayed on the
command line.

### 5. Download and decrypt from a remote

To retrieve your data, download and decrypt in one step:

    python3 lastsafe.py download-decrypt remote:backup /path/to/local_restore \
        --key-dir keys

The tool downloads the encrypted files into a temporary directory
using `rclone copy`, decrypts them with your `private.key` and
writes the plaintext into `/path/to/local_restore`.

## How it works

When encrypting a file, `lastsafe` performs the following steps:

1. **Key encapsulation:** using liboqs’s `KeyEncapsulation` class, a
   random shared secret is derived for the recipient’s public key.  The
   encapsulation yields a small ciphertext and a shared secret.
2. **Symmetric encryption:** the first 32 bytes of the shared secret are
   used as an AES‑256 key.  A 12‑byte random nonce is generated and the
   file contents are encrypted using AES‑GCM (authenticated
   encryption).
3. **Packaging:** the output file begins with a 32‑bit big‑endian
   integer containing the length of the KEM ciphertext, followed by the
   KEM ciphertext itself, the AES nonce and finally the AES‑GCM
   ciphertext and authentication tag.
4. **Upload:** the encrypted files are copied to the remote using rclone.

To decrypt, `lastsafe` reads the header, decapsulates the shared
secret with your private key and then uses AES‑GCM to recover the
plaintext.

## Security considerations

This project is a proof‑of‑concept demonstration.  liboqs emphasises
that its implementations are intended for research and prototyping【901244997312077†L475-L493】.
Security margins may change as post‑quantum cryptography matures; you
should follow NIST guidance on deploying quantum‑safe algorithms and
consider hybrid cryptography【901244997312077†L475-L493】.  Always protect your
private key (`private.key`); anyone who obtains it can decrypt your
data.

## License

This repository contains original code released under the MIT
license.  It depends on third‑party packages which have their own
licenses; consult their respective repositories for details.