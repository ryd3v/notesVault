from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

salt = os.urandom(16)  # Ideally, this should be stored securely for later use.


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def save_salt(salt, filename='salt.dat'):
    with open(filename, 'wb') as f:
        f.write(salt)


def load_salt(filename='salt.dat'):
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None


def encrypt(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message


def decrypt(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message
