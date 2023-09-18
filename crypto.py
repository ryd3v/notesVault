import base64
import os

from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher

# Argon2 settings
ph = PasswordHasher(
    time_cost=2,
    memory_cost=2097152,
    parallelism=8,
    hash_len=32,
    salt_len=16
)


def derive_key(password, salt):
    argon2_hash = ph.hash(password.decode() + salt.hex())
    return argon2_hash.encode()[:32]


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
    backend = default_backend()
    algorithm = algorithms.AES(key)
    iv = os.urandom(12)  # GCM standard
    cipher = Cipher(algorithm, modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encryptor.tag + ct)


def decrypt(encrypted_message, key):
    backend = default_backend()
    encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message)
    iv, tag, ct = encrypted_message_bytes[:12], encrypted_message_bytes[12:28], encrypted_message_bytes[28:]
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode('utf-8')
