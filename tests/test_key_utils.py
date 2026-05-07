import pytest

from crypto_utils.key_utils import (
    save_key_to_hex_file,
    load_public_key_from_hex_file,
    load_private_key_from_hex_file,
)


def test_save_and_load_public_key(tmp_path):
    public_key = (3233, 17)
    key_path = tmp_path / "public_key.hex"

    save_key_to_hex_file(public_key, str(key_path))

    loaded_key = load_public_key_from_hex_file(str(key_path))

    assert loaded_key == public_key


def test_save_and_load_private_key(tmp_path):
    private_key = (3233, 2753)
    key_path = tmp_path / "private_key.hex"

    save_key_to_hex_file(private_key, str(key_path))

    loaded_key = load_private_key_from_hex_file(str(key_path))

    assert loaded_key == private_key


def test_load_key_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_public_key_from_hex_file("missing_key.hex")


def test_load_invalid_hex_key(tmp_path):
    key_path = tmp_path / "invalid_key.hex"
    key_path.write_text("this is not hex", encoding="utf-8")

    with pytest.raises(ValueError):
        load_public_key_from_hex_file(str(key_path))


def test_load_invalid_key_format(tmp_path):
    key_path = tmp_path / "invalid_format.hex"

    invalid_key_string = "3233-17"
    key_path.write_text(invalid_key_string.encode("utf-8").hex(), encoding="utf-8")

    with pytest.raises(ValueError):
        load_public_key_from_hex_file(str(key_path))