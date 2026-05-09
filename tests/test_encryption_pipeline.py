import os

import pytest

from crypto_utils.encryptor import encrypt_file
from crypto_utils.decryptor import decrypt_file
from crypto_utils.oaep import oaep_encode, oaep_decode
from crypto_utils.rsa_core import generate_keypair, get_key_size_bytes


def test_oaep_round_trip_small_message():
    public_key, _ = generate_keypair(bits=1024)
    key_size_bytes = get_key_size_bytes(public_key)

    message = b"hello oaep"
    encoded = oaep_encode(message, key_size_bytes, hash_name="sha256")
    decoded = oaep_decode(encoded, key_size_bytes, hash_name="sha256")

    assert decoded == message


def test_encrypt_decrypt_file_round_trip(tmp_path):
    public_key, private_key = generate_keypair(bits=1024)

    plaintext_path = tmp_path / "plain.bin"
    ciphertext_path = tmp_path / "cipher.bin"
    output_path = tmp_path / "plain_out.bin"

    data = os.urandom(2048)
    plaintext_path.write_bytes(data)

    encrypt_file(str(plaintext_path), public_key, str(ciphertext_path))
    decrypt_file(str(ciphertext_path), private_key, str(output_path))

    assert output_path.read_bytes() == data


def test_oaep_message_too_large():
    public_key, _ = generate_keypair(bits=1024)
    key_size_bytes = get_key_size_bytes(public_key)

    max_len = key_size_bytes - (2 * 32) - 2
    message = b"a" * (max_len + 1)

    with pytest.raises(ValueError):
        oaep_encode(message, key_size_bytes, hash_name="sha256")
