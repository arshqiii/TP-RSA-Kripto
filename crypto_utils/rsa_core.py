from crypto_utils.number_theory import mod_inverse, gcd
from crypto_utils.prime_utils import generate_distinct_primes

DEFAULT_KEY_SIZE = 2048
DEFAULT_PUBLIC_EXPONENT = 65537


"""
Generate RSA key pair (public and private keys)
Return:
        public_key  = (n, e)
        private_key = (n, d)
"""
def generate_keypair(bits: int = DEFAULT_KEY_SIZE, e: int = DEFAULT_PUBLIC_EXPONENT) -> tuple[tuple[int, int], tuple[int, int]]:
    """
    Generate RSA key pair (public and private keys).

    Returns:
        public_key: (e, n)
        private_key: (d, n)
    """
    if bits < 512:
        raise ValueError("Ukuran kunci minimal adalah 512 bit.")
    if bits % 2 != 0:
        raise ValueError("Jumlah bit harus genap.")
    if e <= 1 or e % 2 == 0:
        raise ValueError("Eksponen publik harus bilangan ganjil lebih besar dari 1.")
    
    prime_bits = bits // 2
    while True:
        p, q = generate_distinct_primes(bits=prime_bits)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        if n.bit_length() != bits:
            continue  # Pastikan n memiliki panjang bit yang benar
        
        if gcd(e, phi_n) != 1:
            continue  # Pastikan e coprime dengan phi(n)
        
        d = mod_inverse(e, phi_n)
        public_key = (n, e)
        private_key = (n, d)
        
        return public_key, private_key
    
    
"""
RSA encryption and decryption functions for integers.
Rumus : 
- Encrypt: ciphertext = (message^e) mod n
- Decrypt: message = (ciphertext^d) mod n
"""
def encrypt_rsa_int(message_int: int, public_key: tuple[int, int]) -> int:
    n, e = public_key
    if message_int < 0 or message_int >= n:
        raise ValueError("Pesan harus dalam rentang [0, n-1].")
    return pow(message_int, e, n)

def decrypt_rsa_int(ciphertext_int: int, private_key: tuple[int, int]) -> int:
    n, d = private_key
    if ciphertext_int < 0 or ciphertext_int >= n:
        raise ValueError("Ciphertext harus dalam rentang [0, n-1].")
    return pow(ciphertext_int, d, n)

"""Mengambil ukuran kunci dalam byte dari key RSA."""
def get_key_size_bytes(key: tuple[int, int]) -> int:
    n, _ = key
    return (n.bit_length() + 7) // 8

"""Validasi pasangan kunci RSA dengan mengenkripsi dan mendekripsi pesan uji coba."""
def validate_key_pair(public_key: tuple[int, int], private_key: tuple[int, int]) -> bool:
    public_n, _ = public_key
    private_n, _ = private_key
    
    if public_n != private_n:
        return False  # n harus sama untuk public dan private key
    
    test_message = 42  # buat uji coba
    ciphertext = encrypt_rsa_int(test_message, public_key)
    decrypted = decrypt_rsa_int(ciphertext, private_key)
    
    return decrypted == test_message  