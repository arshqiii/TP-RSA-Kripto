
def gcd(a: int, b: int) -> int:
    """
    Menghitung greatest common divisor dari a dan b
    menggunakan Euclidean Algorithm.
    """
    a = abs(a)
    b = abs(b)

    while b:
        a, b = b, a % b

    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Menghitung gcd(a, b) dan koefisien x, y sehingga:

        a*x + b*y = gcd(a, b)

    Return:
        (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1

    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return g, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Menghitung modular inverse dari a terhadap m.

    Mencari x sehingga:

        (a * x) % m == 1

    Modular inverse hanya ada jika gcd(a, m) == 1.
    """
    if m <= 0:
        raise ValueError("Modulus m harus lebih besar dari 0.")

    a = a % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse tidak ada karena gcd({a}, {m}) = {g}.")

    return x % m


def int_to_bytes(n: int, length: int) -> bytes:
    """
    Mengubah integer menjadi bytes dengan panjang tertentu.

    Contoh:
        int_to_bytes(65, 2) -> b'\\x00A'
    """
    if n < 0:
        raise ValueError("Integer tidak boleh negatif.")

    if length <= 0:
        raise ValueError("Length harus lebih besar dari 0.")

    max_value = 1 << (8 * length)

    if n >= max_value:
        raise ValueError(f"Integer terlalu besar untuk direpresentasikan dalam {length} byte.")

    return n.to_bytes(length, byteorder="big")


def bytes_to_int(b: bytes) -> int:
    """
    Mengubah bytes menjadi integer.

    Contoh:
        bytes_to_int(b'\\x00A') -> 65
    """
    if not isinstance(b, bytes):
        raise TypeError("Input harus bertipe bytes.")

    return int.from_bytes(b, byteorder="big")