from cryptography.fernet import Fernet
from argon2 import PasswordHasher
import base64

# Argon2 settings
ph = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,
    parallelism=1,
    hash_len=32,
    salt_len=16
)


def derive_key(password, salt):
    argon2_hash = ph.hash(password.decode() + salt.hex())
    key = base64.urlsafe_b64encode(argon2_hash.encode()[:32])
    return key


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
