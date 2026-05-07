import pytest

from crypto_utils.number_theory import (
    gcd,
    extended_gcd,
    mod_inverse,
    int_to_bytes,
    bytes_to_int,
)


def test_gcd():
    assert gcd(12, 8) == 4
    assert gcd(17, 3120) == 1
    assert gcd(-12, 8) == 4


def test_extended_gcd():
    g, x, y = extended_gcd(17, 3120)

    assert g == 1
    assert (17 * x + 3120 * y) == g


def test_mod_inverse():
    assert mod_inverse(17, 3120) == 2753
    assert (17 * mod_inverse(17, 3120)) % 3120 == 1


def test_mod_inverse_not_exist():
    with pytest.raises(ValueError):
        mod_inverse(6, 12)


def test_int_to_bytes_and_bytes_to_int():
    n = 65
    b = int_to_bytes(n, 2)

    assert b == b"\x00A"
    assert bytes_to_int(b) == n


def test_int_to_bytes_too_large():
    with pytest.raises(ValueError):
        int_to_bytes(256, 1)