from crypto_utils.prime_utils import (
    generate_odd_candidate,
    is_probable_prime,
    generate_prime,
    generate_distinct_primes,
)


def test_generate_odd_candidate():
    candidate = generate_odd_candidate(16)

    assert candidate.bit_length() == 16
    assert candidate % 2 == 1


def test_is_probable_prime_small_primes():
    assert is_probable_prime(2)
    assert is_probable_prime(3)
    assert is_probable_prime(5)
    assert is_probable_prime(17)
    assert is_probable_prime(65537)


def test_is_probable_prime_composites():
    assert not is_probable_prime(1)
    assert not is_probable_prime(4)
    assert not is_probable_prime(15)
    assert not is_probable_prime(21)
    assert not is_probable_prime(100)


def test_generate_prime_small_bits():
    prime = generate_prime(bits=16, rounds=10)

    assert prime.bit_length() == 16
    assert prime % 2 == 1
    assert is_probable_prime(prime, rounds=10)


def test_generate_distinct_primes():
    p, q = generate_distinct_primes(bits=16, rounds=10)

    assert p != q
    assert is_probable_prime(p, rounds=10)
    assert is_probable_prime(q, rounds=10)