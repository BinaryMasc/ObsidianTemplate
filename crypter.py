import os
import sys
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# pip install cryptography

def generate_sha512_hash(data: str) -> str:
    data_bytes = data.encode('utf-8')
    sha512 = hashlib.sha512()
    sha512.update(data_bytes)
    hash_hex = sha512.hexdigest()
    return hash_hex

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def encrypt_data(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(data: bytes, key: bytes) -> bytes:
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded_data = decryptor.update(data[16:]) + decryptor.finalize()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def encrypt_file(file_path: str, key: bytes):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    encrypted_data = encrypt_data(plaintext, key)
    directory = file_path.rsplit('\\', 1)[0]
    encrypted_filename = directory + '\\' + encrypt_data(file_path.encode(), key).hex() + '.obsencrypt'
    with open(encrypted_filename, 'wb') as f:
        f.write(encrypted_data)
    os.remove(file_path)

def decrypt_file(file_path: str, key: bytes):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_data(encrypted_data, key)
    encrypted_filename = (file_path.rsplit('.', 1)[0]).split('\\')[-1]
    directory = file_path.rsplit('\\', 1)[0]
    
    original_filename =  decrypt_data(bytes.fromhex(encrypted_filename), key).decode()

    with open(original_filename, 'wb') as f:
        f.write(decrypted_data)
    os.remove(file_path)

def process_directory(directory: str, key: bytes, encrypt: bool):
    for root, _, files in os.walk(directory):
        for file in files:
            if file == "crypter.py":
                continue;
            file_path = os.path.join(root, file)
            try:
                if encrypt:
                    encrypt_file(file_path, key)
                elif file.endswith(".obsencrypt"):
                    decrypt_file(file_path, key)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")

if __name__ == "__main__":
    args_count = len(sys.argv)
    if args_count != 4 and args_count != 2:
        #print("Usage: python script.py <directory> <password> <encrypt|decrypt>")
        #sys.exit(1)
        action = "decrypt" if os.path.exists(".hash") else "encrypt"
        directory = "Encrypted Vault"
        password = input("Password: ")

    elif args_count == 4:
        directory = sys.argv[1]
        password = sys.argv[2]
        action = sys.argv[3]

    elif args_count == 2:
        if sys.argv[1] == "encrypt":
            if os.path.isfile(".hash"):
                print("(!) Files already encrypted.")
                sys.exit(1)
            action = sys.argv[1]
        directory = "Encrypted Vault"
        password = input("Password: ")

   

    key = derive_key(password)
    hash = generate_sha512_hash(password + "obsencrypt")
    #print(hash)


    if action == 'encrypt':
        open(".hash", "w").write(hash)
        process_directory(directory, key, encrypt=True)
    elif action == 'decrypt':
        if open(".hash", "r").read() != hash:
            print("(!) Incorrect password.")
            input()
            sys.exit(1)
        process_directory(directory, key, encrypt=False)
        os.remove(".hash")
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)
