from crypto_utils.rsa_core import generate_keypair
from crypto_utils.key_utils import save_key_to_hex_file

def main():
    print("Generating RSA key pair...")
    public_key, private_key = generate_keypair(bits=2048)
    
    print("Saving public key to 'public_key.hex'...")
    save_key_to_hex_file(public_key, "keys/public_key.hex")
    
    print("Saving private key to 'private_key.hex'...")
    save_key_to_hex_file(private_key, "keys/private_key.hex")
    
    print("Keys generated and saved successfully.")
    print("public_key: keys/public_key.hex")
    print("private_key: keys/private_key.hex")
    
if __name__ == "__main__":
    main()