#!/bin/bash
# Basic functionality test for lastsafe

set -e  # Exit on error

echo "==================================="
echo "Lastsafe Basic Functionality Test"
echo "==================================="

# Clean up any previous test files
rm -rf test_keys test_plain test_encrypted test_decrypted

echo ""
echo "1. Testing key generation..."
python3 lastsafe.py generate-keys --out test_keys
if [ -f "test_keys/public.key" ] && [ -f "test_keys/private.key" ]; then
    echo "   ✓ Keys generated successfully"
else
    echo "   ✗ Key generation failed"
    exit 1
fi

echo ""
echo "2. Creating test files..."
mkdir -p test_plain
echo "This is a secret message for PQC testing!" > test_plain/secret.txt
echo "Another secret file" > test_plain/secret2.txt
mkdir -p test_plain/subdir
echo "File in subdirectory" > test_plain/subdir/nested.txt
echo "   ✓ Test files created"

echo ""
echo "3. Testing file encryption..."
python3 lastsafe.py encrypt test_plain/secret.txt test_encrypted_file --key-dir test_keys
if [ -f "test_encrypted_file" ]; then
    echo "   ✓ File encrypted successfully"
else
    echo "   ✗ File encryption failed"
    exit 1
fi

echo ""
echo "4. Testing file decryption..."
python3 lastsafe.py decrypt test_encrypted_file test_decrypted_file --key-dir test_keys
if [ -f "test_decrypted_file" ]; then
    ORIGINAL=$(cat test_plain/secret.txt)
    DECRYPTED=$(cat test_decrypted_file)
    if [ "$ORIGINAL" = "$DECRYPTED" ]; then
        echo "   ✓ File decrypted successfully and content matches!"
    else
        echo "   ✗ Decrypted content doesn't match original"
        exit 1
    fi
else
    echo "   ✗ File decryption failed"
    exit 1
fi

echo ""
echo "5. Testing directory encryption..."
python3 lastsafe.py encrypt test_plain test_encrypted --key-dir test_keys
if [ -d "test_encrypted" ]; then
    FILE_COUNT=$(find test_encrypted -type f | wc -l)
    if [ "$FILE_COUNT" -eq 3 ]; then
        echo "   ✓ Directory encrypted successfully ($FILE_COUNT files)"
    else
        echo "   ✗ Unexpected number of encrypted files: $FILE_COUNT"
        exit 1
    fi
else
    echo "   ✗ Directory encryption failed"
    exit 1
fi

echo ""
echo "6. Testing directory decryption..."
python3 lastsafe.py decrypt test_encrypted test_decrypted --key-dir test_keys
if [ -d "test_decrypted" ]; then
    ORIG_CONTENT=$(cat test_plain/secret.txt)
    DEC_CONTENT=$(cat test_decrypted/secret.txt)
    if [ "$ORIG_CONTENT" = "$DEC_CONTENT" ]; then
        echo "   ✓ Directory decrypted successfully!"
    else
        echo "   ✗ Decrypted content doesn't match"
        exit 1
    fi

    # Check subdirectory
    if [ -f "test_decrypted/subdir/nested.txt" ]; then
        echo "   ✓ Subdirectory structure preserved"
    else
        echo "   ✗ Subdirectory structure not preserved"
        exit 1
    fi
else
    echo "   ✗ Directory decryption failed"
    exit 1
fi

echo ""
echo "7. Testing help command..."
python3 lastsafe.py --help > /dev/null 2>&1
echo "   ✓ Help command works"

echo ""
echo "==================================="
echo "All basic tests passed! ✓"
echo "==================================="
echo ""
echo "The following features have been verified:"
echo "  - Key generation (ML-KEM-512)"
echo "  - File encryption/decryption"
echo "  - Directory encryption/decryption"
echo "  - Directory structure preservation"
echo ""
echo "Note: Peer-to-peer transfer requires two machines"
echo "      and cannot be tested in this script."
echo ""
echo "Cleaning up test files..."
rm -rf test_keys test_plain test_encrypted test_decrypted test_encrypted_file test_decrypted_file
echo "Done!"
