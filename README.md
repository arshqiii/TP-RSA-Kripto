# RSA-OAEP-256 File Encryption and Decryption

This project is a Python implementation of RSA-OAEP-256 file encryption and
decryption for the CSCE 604243 Cryptography & Information Security assignment.
It uses 2048-bit RSA keys and supports arbitrary binary files, including text,
images, audio, video, documents, and executable-like binary data.

The project includes a Tkinter GUI for demo use and CLI scripts for direct
testing.

## Important Note

This project does not use existing RSA/OAEP cryptography libraries such as
`cryptography`, `pycryptodome`, `rsa`, or OpenSSL wrappers. RSA, OAEP, MGF1,
key generation, and file encryption/decryption are implemented in the project
code. Python's standard `hashlib` is used only for SHA-256 hashing and OAEP's
SHA-256 primitive.

## Team

- Muhammad Radhiya Arshq (2306275885)
- Ahmad Dzulfikar As Shavy (2306152374)
- Figo Favian Ragazo (2306241764)

## Project Structure

- `crypto_utils/`: RSA core, number theory, prime generation, OAEP, key file
  handling, file encryption/decryption, hash validation, and ciphertext format
  validation.
- `scripts/`: CLI entry points for generating keys, encrypting files, and
  decrypting files.
- `gui/`: Tkinter GUI application.
- `tests/`: Unit tests and end-to-end tests.
- `keys/`: Default output directory for generated key files.
- `outputs/`: Suggested output directory for ciphertext and decrypted files.
- `test_files/`: Suggested directory for demo input files.

## Run the GUI

```bash
python main.py
```

GUI demo flow:

1. Generate a 2048-bit RSA key pair.
2. Choose a plaintext file.
3. The GUI automatically sets the decryption output to
   `outputs/decrypted_<original_filename>` so the decrypted file keeps the
   original extension, for example `decrypted_video.mp4`.
4. Encrypt it with `keys/public_key.hex`.
5. Decrypt the ciphertext with `keys/private_key.hex`.
6. Compare the SHA-256 hash of the original and decrypted files.
7. A `MATCH` result proves the decrypted file is identical to the original.

## Generate Keys with CLI

```bash
python -m scripts.generate_keys
```

This writes:

- `keys/public_key.hex`
- `keys/private_key.hex`

## Encrypt with CLI

```bash
python -m scripts.encrypt_file <plaintext_path> <public_key_path> <output_ciphertext_path>
```

Example:

```bash
python -m scripts.encrypt_file test_files/plaintext.txt keys/public_key.hex outputs/encrypted.bin
```

## Decrypt with CLI

```bash
python -m scripts.decrypt_file <ciphertext_path> <private_key_path> <output_plaintext_path>
```

Example:

```bash
python -m scripts.decrypt_file outputs/encrypted.bin keys/private_key.hex outputs/decrypted.txt
```

## SHA-256 Hash Validation

The GUI can compare the SHA-256 digest of the original file and the decrypted
file. If both hashes are identical, the decrypted output matches the original
byte-for-byte.

The helper function is:

```python
from crypto_utils.hash_utils import sha256_file

digest = sha256_file("outputs/decrypted.txt")
```

## Key Format

Key files are text files containing hexadecimal-encoded UTF-8 text.

After hex decoding, the key format is:

```text
n_decimal:exponent_decimal
```

Public key files use:

```text
n:e
```

Private key files use:

```text
n:d
```

## Ciphertext Format

Ciphertext files contain repeated encrypted blocks:

```text
4 bytes: block length, big-endian unsigned integer
256 bytes: RSA-OAEP-256 ciphertext block
```

The same pattern repeats until the end of the file. The helper
`validate_ciphertext_format()` checks the container format without decrypting.

## Run Tests

Install test dependencies if needed:

```bash
pip install -r requirements.txt
```

Run all tests:

```bash
pytest
```

or:

```bash
python -m pytest
```
