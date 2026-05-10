import struct

import pytest

from crypto_utils.cipher_format import validate_ciphertext_format


def test_validate_ciphertext_format_valid(tmp_path):
    ciphertext_path = tmp_path / "valid_ciphertext.bin"
    block = b"\x42" * 256
    ciphertext_path.write_bytes(struct.pack(">I", len(block)) + block)

    assert validate_ciphertext_format(str(ciphertext_path))


def test_validate_ciphertext_format_truncated_header(tmp_path):
    ciphertext_path = tmp_path / "truncated_header.bin"
    ciphertext_path.write_bytes(b"\x00\x00")

    with pytest.raises(ValueError, match="incomplete block length header"):
        validate_ciphertext_format(str(ciphertext_path))


def test_validate_ciphertext_format_wrong_block_length(tmp_path):
    ciphertext_path = tmp_path / "wrong_length.bin"
    block = b"\x00" * 128
    ciphertext_path.write_bytes(struct.pack(">I", len(block)) + block)

    with pytest.raises(ValueError, match="expected 256 bytes"):
        validate_ciphertext_format(str(ciphertext_path))


def test_validate_ciphertext_format_truncated_block(tmp_path):
    ciphertext_path = tmp_path / "truncated_block.bin"
    block = b"\x00" * 100
    ciphertext_path.write_bytes(struct.pack(">I", 256) + block)

    with pytest.raises(ValueError, match="truncated in block"):
        validate_ciphertext_format(str(ciphertext_path))


def test_validate_ciphertext_format_custom_block_size(tmp_path):
    ciphertext_path = tmp_path / "valid_128_byte_blocks.bin"
    block = b"\x11" * 128
    ciphertext_path.write_bytes(struct.pack(">I", len(block)) + block)

    assert validate_ciphertext_format(str(ciphertext_path), block_size=128)
