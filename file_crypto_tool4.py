import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import secrets

# Derive AES-256 key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 = 32 bytes
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file
def encrypt_file(input_file, output_file, password):
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    key = derive_key(password, salt)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Pad manually to 16-byte blocks
    padding_len = 16 - len(plaintext) % 16
    plaintext += bytes([padding_len]) * padding_len

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save salt + iv + ciphertext
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print(f"[+] File encrypted and saved as {output_file}")

# Decrypt a file
def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        file_data = f.read()

    salt = file_data[:16]
    iv = file_data[16:32]
    ciphertext = file_data[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_len = decrypted[-1]
    plaintext = decrypted[:-padding_len]

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"[+] File decrypted and saved as {output_file}")

# CLI Menu
if __name__ == "__main__":
    print("--- FILE ENCRYPTION TOOL (AES-256) ---")
    print("1. Encrypt File")
    print("2. Decrypt File")
    choice = input("Choose an option (1/2): ")

    if choice == "1":
        in_file = input("Enter file path to encrypt: ")
        out_file = input("Enter output file path (e.g., secret.enc): ")
        pwd = input("Enter password: ")
        encrypt_file(in_file, out_file, pwd)

    elif choice == "2":
        in_file = input("Enter encrypted file path: ")
        out_file = input("Enter output file name (e.g., decrypted.txt): ")
        pwd = input("Enter password: ")
        try:
            decrypt_file(in_file, out_file, pwd)
        except Exception as e:
            print("[-] Decryption failed. Wrong password or corrupted file.")
    else:
        print("Invalid option.")
