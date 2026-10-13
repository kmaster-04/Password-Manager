# tests/test_crypto_utils.py

import pytest
from crypto_utils import (
    generate_salt,
    generate_nonce,
    derive_key,
    encrypt_vault,
    decrypt_vault,
)

def test_salt_and_nonce_lengths():
    salt = generate_salt()
    nonce = generate_nonce()
    assert len(salt) == 16
    assert len(nonce) == 12

def test_key_derivation_is_deterministic():
    password = "correct horse battery staple"
    salt = b"1234567890abcdef"  # fixed salt for test
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2
    assert len(key1) == 32  # 256 bits

def test_encrypt_decrypt_roundtrip():
    password = "testpassword"
    salt = generate_salt()
    key = derive_key(password, salt)
    plaintext = '{"service": "example.com", "username": "alice", "password": "secret"}'
    
    nonce, ciphertext = encrypt_vault(plaintext, key)
    decrypted = decrypt_vault(nonce, ciphertext, key)
    
    assert decrypted == plaintext

def test_wrong_password_fails():
    password = "correctpassword"
    wrong_password = "wrongpassword"
    salt = generate_salt()
    key_correct = derive_key(password, salt)
    key_wrong = derive_key(wrong_password, salt)
    
    plaintext = "sensitive data"
    nonce, ciphertext = encrypt_vault(plaintext, key_correct)
    
    with pytest.raises(Exception):
        decrypt_vault(nonce, ciphertext, key_wrong)

def test_tampered_ciphertext_is_rejected():
    password = "testpassword"
    salt = generate_salt()
    key = derive_key(password, salt)
    plaintext = "attack at dawn"
    nonce, ciphertext = encrypt_vault(plaintext, key)
    
    # Flip a byte in the ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    tampered_bytes = bytes(tampered)
    
    with pytest.raises(Exception):
        decrypt_vault(nonce, tampered_bytes, key)