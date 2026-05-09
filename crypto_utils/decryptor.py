import struct
from pathlib import Path

from crypto_utils.oaep import oaep_decode
from crypto_utils.rsa_core import decrypt_rsa_int, get_key_size_bytes
from crypto_utils.number_theory import bytes_to_int, int_to_bytes


def _read_exact(fin, length: int) -> bytes:
    data = fin.read(length)
    if len(data) != length:
        raise ValueError("Ciphertext terpotong atau format tidak valid.")
    return data


def decrypt_file(ciphertext_path: str, private_key: tuple[int, int], output_path: str) -> dict:
    input_file = Path(ciphertext_path)
    output_file = Path(output_path)

    if not input_file.is_file():
        raise FileNotFoundError(f"File input tidak ditemukan: {input_path}")

    key_size_bytes = get_key_size_bytes(private_key)

    total_blocks = 0
    total_bytes = 0

    with input_file.open("rb") as fin, output_file.open("wb") as fout:
        while True:
            length_prefix = fin.read(4)
            if not length_prefix:
                break
            if len(length_prefix) != 4:
                raise ValueError("Format ciphertext tidak valid (prefix).")

            block_len = struct.unpack(">I", length_prefix)[0]
            if block_len != key_size_bytes:
                raise ValueError("Panjang blok ciphertext tidak sesuai dengan ukuran key.")

            cipher_bytes = _read_exact(fin, block_len)
            cipher_int = bytes_to_int(cipher_bytes)
            message_int = decrypt_rsa_int(cipher_int, private_key)
            encoded = int_to_bytes(message_int, key_size_bytes)
            plaintext = oaep_decode(encoded, key_size_bytes, hash_name="sha256")

            fout.write(plaintext)

            total_blocks += 1
            total_bytes += len(plaintext)

    return {
        "blocks": total_blocks,
        "output_bytes": total_bytes,
        "output_path": str(output_file),
    }
