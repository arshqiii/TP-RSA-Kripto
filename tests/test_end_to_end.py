import pytest

from crypto_utils.cipher_format import validate_ciphertext_format
from crypto_utils.decryptor import decrypt_file
from crypto_utils.encryptor import encrypt_file
from crypto_utils.hash_utils import sha256_file
from crypto_utils.rsa_core import generate_keypair, get_key_size_bytes


def _deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes(((index * 37) + seed) % 256 for index in range(size))


@pytest.fixture(scope="module")
def rsa_2048_keypair():
    return generate_keypair(bits=2048)


@pytest.mark.parametrize(
    ("filename", "data"),
    [
        ("message.txt", ("RSA-OAEP-256 handles text files.\n" * 12).encode("utf-8")),
        ("image.png", b"\x89PNG\r\n\x1a\n" + _deterministic_bytes(320, 3)),
        ("audio.wav", b"RIFF" + _deterministic_bytes(360, 17)),
        ("video.mp4", b"\x00\x00\x00\x18ftypmp42" + _deterministic_bytes(420, 29)),
        ("binary.bin", _deterministic_bytes(512, 91)),
    ],
)
def test_encrypt_decrypt_2048_bit_key_multiple_file_types(
    tmp_path, rsa_2048_keypair, filename, data
):
    public_key, private_key = rsa_2048_keypair
    assert get_key_size_bytes(public_key) == 256

    plaintext_path = tmp_path / filename
    ciphertext_path = tmp_path / f"{filename}.enc"
    output_path = tmp_path / f"decrypted_{filename}"
    plaintext_path.write_bytes(data)

    encrypt_result = encrypt_file(str(plaintext_path), public_key, str(ciphertext_path))
    assert encrypt_result["input_bytes"] == len(data)
    assert encrypt_result["blocks"] >= 1

    assert validate_ciphertext_format(
        str(ciphertext_path),
        block_size=get_key_size_bytes(public_key),
    )

    decrypt_result = decrypt_file(str(ciphertext_path), private_key, str(output_path))
    assert decrypt_result["output_bytes"] == len(data)

    assert sha256_file(str(output_path)) == sha256_file(str(plaintext_path))
    assert output_path.read_bytes() == data


def test_sha256_file_known_digest(tmp_path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"abc")

    assert sha256_file(str(file_path)) == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )
