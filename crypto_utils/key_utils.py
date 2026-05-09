from pathlib import Path

def save_key_to_hex_file(key: tuple[int, int], output_path: str):
    output_file = Path(output_path)
    
    if not isinstance(key, tuple) or len(key) != 2:
        raise ValueError("Key harus berupa tuple (n, exponent).")

    n, exp = key

    if not isinstance(n, int) or not isinstance(exp, int):
        raise TypeError("Nilai n dan exponent harus bertipe int.")

    if n <= 0 or exp <= 0:
        raise ValueError("Nilai n dan exponent harus lebih besar dari 0.")

    key_string = f"{n}:{exp}"

    key_bytes = key_string.encode("utf-8")
    key_hex = key_bytes.hex()
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(key_hex, encoding="utf-8")   

def _load_key_from_hex_file(key_path: str):
    key_path = Path(key_path)
    
    if not key_path.is_file():
        raise FileNotFoundError(f"File {key_path} tidak ditemukan.")
    
    key_path = key_path.read_text(encoding="utf-8").strip()
    
    if not key_path:
        raise ValueError("File key kosong.")
    
    try :
        key_bytes = bytes.fromhex(key_path)
        key_string = key_bytes.decode("utf-8")
        n_str, exp_str = key_string.split(":")
        n = int(n_str)
        exp = int(exp_str)
    except Exception as e:
        raise ValueError(f"Format key tidak valid: {e}")
    
    return n, exp

def load_public_key_from_hex_file(key_path: str):
    return _load_key_from_hex_file(key_path)
    
def load_private_key_from_hex_file(key_path: str):
    return _load_key_from_hex_file(key_path)