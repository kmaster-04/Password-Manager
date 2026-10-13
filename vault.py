# vault.py

import json
import base64
import os

from crypto_utils import (
    generate_salt,
    derive_key,
    encrypt_vault,
    decrypt_vault,
)

# Separator used in the vault file
SEPARATOR = "|"

def _read_vault_file(vault_path: str):
    """Read the raw vault file and return (salt, nonce, ciphertext) as bytes."""
    with open(vault_path, "r") as f:
        data = f.read().strip()
    salt_b64, nonce_b64, ct_b64 = data.split(SEPARATOR)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ct_b64)
    return salt, nonce, ciphertext

def _write_vault_file(vault_path: str, salt: bytes, nonce: bytes, ciphertext: bytes):
    """Write salt, nonce, and ciphertext to the vault file."""
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    ct_b64 = base64.b64encode(ciphertext).decode('utf-8')
    with open(vault_path, "w") as f:
        f.write(salt_b64 + SEPARATOR + nonce_b64 + SEPARATOR + ct_b64)

def create_vault(vault_path: str, master_password: str):
    """
    Create a new empty vault at vault_path, encrypted with master_password.
    Raises FileExistsError if the vault already exists.
    """
    if os.path.exists(vault_path):
        raise FileExistsError("Vault already exists at " + vault_path)

    salt = generate_salt()
    key = derive_key(master_password, salt)
    empty_list = []
    plaintext = json.dumps(empty_list)
    nonce, ciphertext = encrypt_vault(plaintext, key)
    _write_vault_file(vault_path, salt, nonce, ciphertext)

def load_vault(vault_path: str, master_password: str):
    """
    Decrypt and return the list of credentials from the vault.
    Raises ValueError if decryption fails (wrong password or tampered file).
    """
    if not os.path.exists(vault_path):
        raise FileNotFoundError("Vault not found at " + vault_path)

    salt, nonce, ciphertext = _read_vault_file(vault_path)
    key = derive_key(master_password, salt)
    try:
        plaintext = decrypt_vault(nonce, ciphertext, key)
    except Exception:
        raise ValueError("Incorrect master password or corrupted vault file.")

    credentials = json.loads(plaintext)
    return credentials

def save_vault(vault_path: str, master_password: str, credentials):
    """
    Encrypt and write the given credentials list to the vault file.
    A new salt and nonce are generated for each save, so old salt isn't reused.
    """
    salt = generate_salt()
    key = derive_key(master_password, salt)
    plaintext = json.dumps(credentials)
    nonce, ciphertext = encrypt_vault(plaintext, key)
    _write_vault_file(vault_path, salt, nonce, ciphertext)

# --- CRUD helpers ---

def add_credential(credentials, service, username, password, totp_secret=None):
    """
    Append a new credential to the list.

    The optional totp_secret is a base32-encoded string used to generate
    time-based one-time passwords (RFC 6238). It is stored inside the
    encrypted vault alongside the other fields.
    """
    entry = {
        "service": service,
        "username": username,
        "password": password,
    }
    if totp_secret:
        entry["totp_secret"] = totp_secret
    credentials.append(entry)

def get_credential(credentials, service):
    """Return all matching credentials for a service (case-insensitive substring)."""
    matches = [c for c in credentials if service.lower() in c["service"].lower()]
    return matches

def update_credential(credentials, service, username=None, password=None):
    """
    Update the first credential matching the service.
    If username/password is provided, update those fields.
    Returns True if a credential was updated, False otherwise.
    """
    for c in credentials:
        if service.lower() in c["service"].lower():
            if username is not None:
                c["username"] = username
            if password is not None:
                c["password"] = password
            return True
    return False

def delete_credential(credentials, service):
    """
    Delete all credentials matching the service.
    Returns the number of deleted entries.
    """
    new_list = [c for c in credentials if service.lower() not in c["service"].lower()]
    deleted = len(credentials) - len(new_list)
    credentials.clear()
    credentials.extend(new_list)
    return deleted

def list_credentials(credentials):
    """Return a list of (service, username) tuples, without passwords."""
    return [(c["service"], c["username"]) for c in credentials]

def set_totp_secret(credentials, service, totp_secret):
    """
    Attach or replace the TOTP secret for the first credential matching
    the service name. Returns True if a credential was updated.
    """
    for c in credentials:
        if service.lower() in c["service"].lower():
            c["totp_secret"] = totp_secret
            return True
    return False