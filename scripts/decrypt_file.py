import argparse

from crypto_utils.decryptor import decrypt_file
from crypto_utils.key_utils import load_private_key_from_hex_file


def main():
    parser = argparse.ArgumentParser(description="Decrypt file using RSA-OAEP-256")
    parser.add_argument("ciphertext", help="Path ke file ciphertext")
    parser.add_argument("private_key", help="Path ke private key (hex)")
    parser.add_argument("output", help="Path output plaintext")
    args = parser.parse_args()

    private_key = load_private_key_from_hex_file(args.private_key)
    result = decrypt_file(args.ciphertext, private_key, args.output)

    print("Dekripsi selesai.")
    print(f"Blocks: {result['blocks']}")
    print(f"Output bytes: {result['output_bytes']}")
    print(f"Output: {result['output_path']}")


if __name__ == "__main__":
    main()
