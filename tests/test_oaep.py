import pytest

from crypto_utils.oaep import oaep_encode, oaep_decode
from crypto_utils.rsa_core import generate_keypair, get_key_size_bytes


def test_oaep_round_trip_various_sizes():
    public_key, _ = generate_keypair(bits=1024)
    key_size_bytes = get_key_size_bytes(public_key)

    max_len = key_size_bytes - (2 * 32) - 2

    for size in [0, 1, 2, 8, 16, 31, 32, max_len - 1, max_len]:
        message = b"a" * size
        encoded = oaep_encode(message, key_size_bytes, hash_name="sha256")
        decoded = oaep_decode(encoded, key_size_bytes, hash_name="sha256")
        assert decoded == message


def test_oaep_invalid_label_hash():
    public_key, _ = generate_keypair(bits=1024)
    key_size_bytes = get_key_size_bytes(public_key)

    message = b"test"
    encoded = oaep_encode(message, key_size_bytes, label=b"label1", hash_name="sha256")

    with pytest.raises(ValueError):
        oaep_decode(encoded, key_size_bytes, label=b"label2", hash_name="sha256")
