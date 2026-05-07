import pytest

from crypto_utils.rsa_core import (
    generate_keypair,
    encrypt_rsa_int,
    decrypt_rsa_int,
    get_key_size_bytes,
    validate_key_pair,
)


def test_rsa_small_manual_example():
    """
    p = 61
    q = 53
    n = 3233
    phi = 3120
    e = 17
    d = 2753

    message = 65
    ciphertext = 2790
    """
    public_key = (3233, 17)
    private_key = (3233, 2753)

    message = 65

    ciphertext = encrypt_rsa_int(message, public_key)
    decrypted = decrypt_rsa_int(ciphertext, private_key)

    assert ciphertext == 2790
    assert decrypted == message


def test_generate_keypair_small_size():
    """
    Untuk testing, gunakan 512-bit supaya cepat.
    Untuk program final, gunakan 2048-bit.
    """
    public_key, private_key = generate_keypair(bits=512)

    assert validate_key_pair(public_key, private_key)
    assert get_key_size_bytes(public_key) == 64


def test_rsa_encrypt_message_too_large():
    public_key = (3233, 17)

    with pytest.raises(ValueError):
        encrypt_rsa_int(4000, public_key)


def test_rsa_decrypt_ciphertext_too_large():
    private_key = (3233, 2753)

    with pytest.raises(ValueError):
        decrypt_rsa_int(4000, private_key)