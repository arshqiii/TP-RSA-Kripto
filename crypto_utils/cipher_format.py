"""Validation helpers for the RSA-OAEP ciphertext block container."""

from __future__ import annotations

import struct
from pathlib import Path


def validate_ciphertext_format(ciphertext_path: str, block_size: int = 256) -> bool:
    """Validate the length-prefixed ciphertext format without decrypting it.

    The expected assignment format is repeated blocks of:
    - 4-byte unsigned big-endian block length
    - RSA ciphertext block bytes
    """
    if block_size <= 0:
        raise ValueError("Block size must be greater than 0.")

    path = Path(ciphertext_path)
    offset = 0
    block_index = 0

    with path.open("rb") as file:
        while True:
            length_prefix = file.read(4)
            if not length_prefix:
                return True

            if len(length_prefix) != 4:
                raise ValueError(
                    f"Ciphertext truncated at byte {offset}: incomplete block length header."
                )

            block_index += 1
            block_len = struct.unpack(">I", length_prefix)[0]
            if block_len != block_size:
                raise ValueError(
                    f"Invalid ciphertext block {block_index}: expected {block_size} bytes, "
                    f"got {block_len} bytes."
                )

            block = file.read(block_len)
            if len(block) != block_len:
                raise ValueError(
                    f"Ciphertext truncated in block {block_index}: expected {block_len} bytes, "
                    f"got {len(block)} bytes."
                )

            offset += 4 + block_len
