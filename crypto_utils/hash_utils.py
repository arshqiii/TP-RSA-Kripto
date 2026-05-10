"""File hashing helpers for GUI validation and end-to-end tests."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Return the lowercase SHA-256 hex digest for a file."""
    if chunk_size <= 0:
        raise ValueError("Chunk size must be greater than 0.")

    file_path = Path(path)
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()
