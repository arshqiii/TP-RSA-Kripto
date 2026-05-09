import struct
from pathlib import Path

from crypto_utils.oaep import oaep_encode
from crypto_utils.rsa_core import encrypt_rsa_int, get_key_size_bytes
from crypto_utils.number_theory import bytes_to_int, int_to_bytes


def encrypt_file(plaintext_path: str, public_key: tuple[int, int], output_path: str) -> dict:
    input_file = Path(plaintext_path)
    output_file = Path(output_path)

    if not input_file.is_file():
        raise FileNotFoundError(f"File input tidak ditemukan: {input_path}")

    key_size_bytes = get_key_size_bytes(public_key)
    hash_len = 32
    max_block_size = key_size_bytes - (2 * hash_len) - 2
    if max_block_size <= 0:
        raise ValueError("Key size terlalu kecil untuk OAEP-256.")

    total_blocks = 0
    total_bytes = 0

    with input_file.open("rb") as fin, output_file.open("wb") as fout:
        while True:
            chunk = fin.read(max_block_size)
            if not chunk:
                break

            encoded = oaep_encode(chunk, key_size_bytes, hash_name="sha256")
            message_int = bytes_to_int(encoded)
            cipher_int = encrypt_rsa_int(message_int, public_key)
            cipher_bytes = int_to_bytes(cipher_int, key_size_bytes)

            fout.write(struct.pack(">I", len(cipher_bytes)))
            fout.write(cipher_bytes)

            total_blocks += 1
            total_bytes += len(chunk)

    return {
        "blocks": total_blocks,
        "input_bytes": total_bytes,
        "output_path": str(output_file),
    }
