import os
import shutil
import base64
import shutil
import tarfile
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Constants
KEY_SIZE = 32  # AES-256 key size in bytes
IV_SIZE = 16  # AES block size in bytes
SALT_SIZE = 16  # Salt size in bytes for KDF


def derive_key_from_passphrase(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())


def encrypt_data(data, key):
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data


def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:IV_SIZE]
    encrypted_data = encrypted_data[IV_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError:
        print("Incorrect passphrase")
        exit()
    return data


def create_archive(source_path):
    archive_path = f"{source_path}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(source_path, arcname=os.path.basename(source_path))
    return archive_path


def extract_archive(archive_path, extract_to):
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(path=extract_to)


def encrypt_file_or_directory(path, passphrase):
    # Determine if the path is a file or directory
    if os.path.isdir(path):
        archive_path = create_archive(path)
    else:
        archive_path = path

    # Generate random file encryption key (FEK)
    file_encryption_key = os.urandom(KEY_SIZE)

    # Encrypt the file or archive using FEK and AES-256
    with open(archive_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = encrypt_data(file_data, file_encryption_key)

    with open(archive_path + '.enc', 'wb') as f:
        f.write(encrypted_data)

    # Derive a key from the passphrase using PBKDF2
    salt = os.urandom(SALT_SIZE)
    derived_key = derive_key_from_passphrase(passphrase, salt)

    # Encrypt the FEK using the derived key
    encrypted_fek = encrypt_data(file_encryption_key, derived_key)

    # Store the encrypted FEK and salt
    os.makedirs(".keys", exist_ok=True)
    with open(".keys/" + archive_path + '.key', 'wb') as f:
        f.write(salt + encrypted_fek)

    if os.path.isdir(path):
        os.remove(archive_path)
        current_directory = os.getcwd()
        full_path = os.path.join(current_directory, path)
        shutil.rmtree(full_path)
    else:
        os.remove(path)


def decrypt_file_or_directory(path, is_folder, passphrase):
    # Read the encrypted FEK and salt
    # archive_path = path + '.tar.gz'
    # key_path = path + '.tar.gz.key'
    archive_path = path
    key_path = path
    enc_path = path
    if is_folder:
        archive_path += '.tar.gz'
        key_path += '.tar.gz.key'
        enc_path += '.tar.gz.enc'
    else:
        key_path += '.key'
        enc_path += '.enc'
    # enc_path = path + '.tar.gz.enc'
    try:
        with open(".keys/" + key_path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            encrypted_fek = f.read()
    except FileNotFoundError:
        print("File Not Found!")
        exit()

    # Derive the key from the passphrase using PBKDF2
    derived_key = derive_key_from_passphrase(passphrase, salt)

    # Decrypt the FEK using the derived key
    file_encryption_key = decrypt_data(encrypted_fek, derived_key)

    # Read the encrypted file or archive
    with open(enc_path, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt the file or archive using the FEK
    file_data = decrypt_data(encrypted_data, file_encryption_key)

    # Save the decrypted file or archive
    with open(archive_path, 'wb') as f:
        f.write(file_data)

    # Extract the archive if it was a directory
    if is_folder:
        extract_to = os.path.dirname(path)
        extract_archive(archive_path, extract_to)
        os.remove(archive_path)
    os.remove(".keys/" + key_path)
    os.remove(enc_path)


if __name__ == "__main__":
    choice = input("Do you want to (e)ncrypt or (d)ecrypt a file or directory? ")
    path = input("Enter the file or directory path: ")
    passphrase = getpass("Enter the passphrase: ")

    if choice.lower() == 'e':
        encrypt_file_or_directory(path, passphrase)
        print("Encryption successful.")
    elif choice.lower() == 'd':
        temp = input('Choose y if ur file is folder: ').lower()
        is_folder = temp == 'y' or temp == 'yes'
        decrypt_file_or_directory(path, is_folder, passphrase)
        print("Decryption successful.")
    else:
        print("Invalid choice.")
