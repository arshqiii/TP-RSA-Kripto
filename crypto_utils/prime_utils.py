# crypto_utils/prime_utils.py

import secrets

from crypto_utils.number_theory import gcd


def generate_odd_candidate(bits: int) -> int:
    """
    Generate bilangan ganjil random dengan panjang bit tertentu.

    Untuk RSA 2048-bit, fungsi ini akan dipakai untuk membuat kandidat
    bilangan prima 1024-bit.
    """
    if bits < 2:
        raise ValueError("Jumlah bit minimal harus 2.")

    candidate = secrets.randbits(bits)

    # Pastikan bit paling kiri bernilai 1 agar panjang bit benar-benar sesuai.
    candidate |= (1 << (bits - 1))

    # Pastikan bilangan ganjil.
    candidate |= 1

    return candidate


def is_divisible_by_small_prime(n: int) -> bool:
    """
    Mengecek apakah n habis dibagi oleh bilangan prima kecil.

    Ini bukan primality test utama, tetapi optimasi awal agar kandidat
    komposit sederhana cepat dibuang sebelum Miller-Rabin.
    """
    small_primes = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47
    ]

    for p in small_primes:
        if n == p:
            return False
        if n % p == 0:
            return True

    return False


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """
    Mengecek apakah n kemungkinan besar prima menggunakan Miller-Rabin.

    Miller-Rabin adalah probabilistic primality test.
    Untuk bilangan besar seperti 1024-bit, 40 rounds sudah cukup kuat
    untuk kebutuhan tugas ini.
    """
    if n < 2:
        return False

    if n in (2, 3):
        return True

    if n % 2 == 0:
        return False

    if is_divisible_by_small_prime(n):
        return False

    # Tulis n - 1 sebagai:
    # n - 1 = 2^s * d
    # dengan d ganjil.
    d = n - 1
    s = 0

    while d % 2 == 0:
        s += 1
        d //= 2

    # Miller-Rabin rounds
    for _ in range(rounds):
        # Pilih basis acak a, dengan 2 <= a <= n - 2
        a = secrets.randbelow(n - 3) + 2

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int = 1024, rounds: int = 40) -> int:
    """
    Generate bilangan prima besar dengan panjang bit tertentu.

    Untuk RSA 2048-bit:
        p = generate_prime(1024)
        q = generate_prime(1024)
    """
    if bits < 2:
        raise ValueError("Jumlah bit minimal harus 2.")

    while True:
        candidate = generate_odd_candidate(bits)

        if is_probable_prime(candidate, rounds):
            return candidate


def generate_distinct_primes(bits: int = 1024, rounds: int = 40) -> tuple[int, int]:
    """
    Generate dua bilangan prima berbeda.

    Ini berguna untuk RSA karena p dan q tidak boleh sama.
    """
    p = generate_prime(bits, rounds)

    while True:
        q = generate_prime(bits, rounds)
        if q != p:
            return p, q