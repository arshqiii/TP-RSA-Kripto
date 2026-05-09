import argparse

from crypto_utils.encryptor import encrypt_file
from crypto_utils.key_utils import load_public_key_from_hex_file


def main():
    parser = argparse.ArgumentParser(description="Encrypt file using RSA-OAEP-256")
    parser.add_argument("plaintext", help="Path ke file plaintext")
    parser.add_argument("public_key", help="Path ke public key (hex)")
    parser.add_argument("output", help="Path output ciphertext")
    args = parser.parse_args()

    public_key = load_public_key_from_hex_file(args.public_key)
    result = encrypt_file(args.plaintext, public_key, args.output)

    print("Enkripsi selesai.")
    print(f"Blocks: {result['blocks']}")
    print(f"Input bytes: {result['input_bytes']}")
    print(f"Output: {result['output_path']}")


if __name__ == "__main__":
    main()
