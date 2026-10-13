# passkey.py
"""
Passkey-style vault unlock.

Models the FIDO2/WebAuthn pattern locally:
  - A device holds an EC keypair; the private key never leaves it.
  - An enrollment file stores the public key plus a wrapped copy of
    the master password.
  - Unlock requires proving possession of the private key, then
    decrypting the wrapped password.

Security note: this implementation stores the master password encrypted
under a key derived from the device private key. A production design
would instead wrap the vault's data key. See the report for discussion.
"""

import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature


HKDF_INFO = b"passkey-unlock-v1"


def generate_device_keypair():
    """Generate an EC P-256 keypair for the device."""
    return ec.generate_private_key(ec.SECP256R1())


def save_private_key(private_key, path):
    """Serialise the private key to disk as PEM (unencrypted)."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path):
    """Load a PEM-encoded private key from disk."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _private_key_bytes(private_key):
    """Raw PKCS8 bytes of the private key, used as HKDF input."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _derive_wrapping_key(private_key):
    """Derive a 32-byte AES key from the device private key via HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    )
    return hkdf.derive(_private_key_bytes(private_key))


def _public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def enroll(vault_path, master_password, private_key_path):
    """
    Create a passkey enrollment that allows the vault to be unlocked with
    the device key instead of the master password.

    Writes <vault_path>.passkey and the device private key.
    Returns the path to the enrollment file.
    """
    private_key = generate_device_keypair()
    save_private_key(private_key, private_key_path)

    wrapping_key = _derive_wrapping_key(private_key)
    nonce = os.urandom(12)
    aesgcm = AESGCM(wrapping_key)
    ciphertext = aesgcm.encrypt(nonce, master_password.encode("utf-8"), None)

    enrollment = {
        "version": 1,
        "public_key": base64.b64encode(
            _public_key_bytes(private_key.public_key())
        ).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

    enrollment_path = vault_path + ".passkey"
    with open(enrollment_path, "w") as f:
        json.dump(enrollment, f, indent=2)

    return enrollment_path


def _load_enrollment(path):
    with open(path, "r") as f:
        return json.load(f)


def verify_device(enrollment, private_key):
    """
    Proof of possession: sign a fresh challenge with the private key and
    verify against the public key recorded at enrollment. Models the
    FIDO2 challenge-response step.
    """
    stored_public = serialization.load_der_public_key(
        base64.b64decode(enrollment["public_key"])
    )
    challenge = os.urandom(32)
    signature = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    try:
        stored_public.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def unlock_with_passkey(vault_path, private_key_path):
    """
    Recover the master password using the passkey enrollment.

    Returns the master password string.
    Raises FileNotFoundError if either file is missing, or ValueError if
    verification or decryption fails.
    """
    enrollment_path = vault_path + ".passkey"
    if not os.path.exists(enrollment_path):
        raise FileNotFoundError(f"No passkey enrollment found at {enrollment_path}")
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"No device key found at {private_key_path}")

    enrollment = _load_enrollment(enrollment_path)
    private_key = load_private_key(private_key_path)

    if not verify_device(enrollment, private_key):
        raise ValueError("Device verification failed: key does not match enrollment.")

    wrapping_key = _derive_wrapping_key(private_key)
    nonce = base64.b64decode(enrollment["nonce"])
    ciphertext = base64.b64decode(enrollment["ciphertext"])
    try:
        aesgcm = AESGCM(wrapping_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Failed to decrypt the master password with the device key.")

    return plaintext.decode("utf-8")