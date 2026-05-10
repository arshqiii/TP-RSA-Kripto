"""
INTEGRATION GUIDE FOR GUI DEVELOPMENT (Member 3 / Anggota 3)
============================================================

This document explains how to integrate the encryption/decryption pipeline
(Member 2's work) into your GUI application.

## Quick Start

Your GUI needs to:
1. Load keys from hex files (using Member 1's key_utils)
2. Call encrypt_file() or decrypt_file() with file paths and keys
3. Handle errors gracefully

## API Reference

### Encrypt a file

```python
from crypto_utils.encryptor import encrypt_file
from crypto_utils.key_utils import load_public_key_from_hex_file

# Load public key
public_key = load_public_key_from_hex_file('keys/public_key.hex')

# Encrypt file
result = encrypt_file(
    plaintext_path='plaintext.bin',
    public_key=public_key,
    output_path='encrypted.bin'
)

# result is a dictionary:
# {
#     'blocks': int,           # number of encrypted blocks
#     'input_bytes': int,      # total bytes encrypted
#     'output_path': str       # path to output file
# }
```

### Decrypt a file

```python
from crypto_utils.decryptor import decrypt_file
from crypto_utils.key_utils import load_private_key_from_hex_file

# Load private key
private_key = load_private_key_from_hex_file('keys/private_key.hex')

# Decrypt file
result = decrypt_file(
    ciphertext_path='encrypted.bin',
    private_key=private_key,
    output_path='plaintext.bin'
)

# result is a dictionary:
# {
#     'blocks': int,           # number of decrypted blocks
#     'output_bytes': int,     # total bytes decrypted
#     'output_path': str       # path to output file
# }
```

## Error Handling

Both functions raise exceptions on errors. Your GUI should catch and display them:

```python
from crypto_utils.encryptor import encrypt_file
from crypto_utils.key_utils import load_public_key_from_hex_file

try:
    public_key = load_public_key_from_hex_file(key_path)
    result = encrypt_file(plaintext_path, public_key, output_path)
    print(f"Success! Encrypted {result['blocks']} blocks")
except FileNotFoundError as e:
    print(f"File not found: {e}")
except ValueError as e:
    print(f"Invalid input or corrupted data: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `FileNotFoundError` | Input file doesn't exist | Check file path |
| `ValueError: OAEP decoding error` | Wrong decryption key OR corrupted ciphertext | Use correct private key |
| `ValueError: ciphertext terpotong` | Ciphertext file is truncated/corrupted | Use original encrypted file |
| `ValueError: Key size terlalu kecil` | Key is smaller than 2048-bit | Generate 2048-bit keys |

## Key Format

Keys are stored as hex-encoded text files:
- `keys/public_key.hex` — Contains public key (n, e)
- `keys/private_key.hex` — Contains private key (n, d)

Format inside: `{n_decimal}:{exponent_decimal}` (hex-encoded as UTF-8)

Load them using Member 1's functions:
```python
from crypto_utils.key_utils import (
    load_public_key_from_hex_file,
    load_private_key_from_hex_file
)
```

## Ciphertext Format

Each encrypted file contains blocks in this format:

```
[Block 1]
  4 bytes: block length (big-endian unsigned int) = 256
  256 bytes: RSA-OAEP-256 ciphertext

[Block 2]
  4 bytes: block length = 256
  256 bytes: RSA-OAEP-256 ciphertext

[... more blocks ...]
```

This format is handled automatically by encrypt_file() and decrypt_file().
You don't need to parse it yourself.

## GUI Integration Example

```python
import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_utils.encryptor import encrypt_file
from crypto_utils.decryptor import decrypt_file
from crypto_utils.key_utils import load_public_key_from_hex_file, load_private_key_from_hex_file

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP-256 Encryption")
        
        # ... GUI setup ...
    
    def encrypt(self):
        try:
            plaintext = filedialog.askopenfilename(title="Select plaintext file")
            key_path = filedialog.askopenfilename(title="Select public key")
            output = filedialog.asksaveasfilename(defaultextension=".bin")
            
            if not all([plaintext, key_path, output]):
                return
            
            public_key = load_public_key_from_hex_file(key_path)
            result = encrypt_file(plaintext, public_key, output)
            
            messagebox.showinfo(
                "Success",
                f"Encrypted {result['blocks']} blocks\n"
                f"{result['input_bytes']} bytes → {output}"
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def decrypt(self):
        try:
            ciphertext = filedialog.askopenfilename(title="Select ciphertext file")
            key_path = filedialog.askopenfilename(title="Select private key")
            output = filedialog.asksaveasfilename()
            
            if not all([ciphertext, key_path, output]):
                return
            
            private_key = load_private_key_from_hex_file(key_path)
            result = decrypt_file(ciphertext, private_key, output)
            
            messagebox.showinfo(
                "Success",
                f"Decrypted {result['blocks']} blocks\n"
                f"{result['output_bytes']} bytes → {output}"
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))
```

## Testing Your Integration

```bash
# Generate test keys (or use existing ones)
python -m scripts.generate_keys

# Test with CLI first (to verify pipeline works)
python -m scripts.encrypt_file plaintext.txt keys/public_key.hex encrypted.bin
python -m scripts.decrypt_file encrypted.bin keys/private_key.hex decrypted.txt

# Then integrate into your GUI
```

## Member 2 Files (Ready to Use)

You only need these imports:
- `from crypto_utils.encryptor import encrypt_file`
- `from crypto_utils.decryptor import decrypt_file`
- `from crypto_utils.key_utils import load_public_key_from_hex_file, load_private_key_from_hex_file`

Don't modify the following (they're complete and tested):
- crypto_utils/oaep.py
- crypto_utils/encryptor.py
- crypto_utils/decryptor.py
- crypto_utils/key_utils.py (Member 1 + Member 2's fix for directory creation)
- scripts/encrypt_file.py
- scripts/decrypt_file.py

## Your Responsibilities (Member 3)

From the task description:
- ✅ Member 2 provides: Encryption/decryption pipeline (DONE)
- 🔨 You provide:
  - GUI (tkinter, PyQt, or equivalent)
  - Integration with encrypt/decrypt functions
  - Key generation UI (can call Member 1's script)
  - Ciphertext format validation (if needed)
  - SHA-256 hash validation (optional enhancement)
  - End-to-end testing
  - Test data files
  - Usage documentation

Good luck! 🚀
"""
