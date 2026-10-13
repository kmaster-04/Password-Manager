import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
PBKDF2_ITERATIONS = 1_400_000


def generate_salt() -> bytes:
    return os.urandom(SALT_LENGTH)


def generate_nonce() -> bytes:
    return os.urandom(NONCE_LENGTH)


def derive_key(master_password: str, salt: bytes,
               iterations: int = PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_password.encode('utf-8'))


def encrypt_vault(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce, ciphertext


def decrypt_vault(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')