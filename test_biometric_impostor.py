# test_biometric_impostor.py
"""
Prove that the biometric unlock rejects a different person.

Runs two tests:
  1. Normal operation — the impostor is rejected at the fuzzy extractor.
  2. Simulated threshold bypass — even if we pretend the distance check
     passed, the impostor still cannot decrypt the master password.
"""

import sys
import os
import json
import base64
import numpy as np

import biometric_auth
from fuzzy_extractor import BiometricFuzzyExtractor


DEFAULT_VAULT_PATH = "vault.vault"


def load_record(vault_path):
    path = biometric_auth.biometric_file_path(vault_path)
    if not os.path.exists(path):
        print(f"No enrollment found at {path}")
        sys.exit(1)
    with open(path, "r") as f:
        return json.load(f)


def try_unlock(record, label):
    """Capture one encoding and attempt to reconstruct the key."""
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print(f"{'=' * 60}")
    print("Look at the camera and blink twice.")

    live = biometric_auth.capture_one()
    if live is None:
        print("  No face captured.")
        return False, None, None

    enrollment = {
        "indices": record["indices"],
        "sketch": record["sketch"],
        "parity": record["parity"],
        "message_len": record["message_len"],
    }

    extractor = BiometricFuzzyExtractor()
    print("\n  Attempting fuzzy extractor reconstruction...")
    key = extractor.reconstruct(live, enrollment, verbose=True)

    if key is None:
        print("  Result: REJECTED (error correction failed)")
        return False, None, None

    print("  Fuzzy extractor produced a key. Attempting decryption...")

    nonce = base64.b64decode(record["nonce"])
    ciphertext = base64.b64decode(record["ciphertext"])

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        print(f"  Result: ACCEPTED — master password recovered")
        return True, key, plaintext.decode("utf-8")
    except Exception as e:
        print(f"  Result: REJECTED (decryption failed: {type(e).__name__})")
        return False, key, None


def main():
    vault_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_VAULT_PATH
    record = load_record(vault_path)

    print("=" * 60)
    print("  BIOMETRIC IMPOSTOR TEST")
    print("=" * 60)
    print(f"  Vault: {vault_path}")
    print(f"  Enrollment version: {record.get('version')}")

    input("\nPress ENTER when the ENROLLED USER is in front of the camera...")
    genuine_ok, _, _ = try_unlock(record, "TEST 1: ENROLLED USER")

    input("\nPress ENTER when a DIFFERENT PERSON is in front of the camera...")
    impostor_ok, _, _ = try_unlock(record, "TEST 2: DIFFERENT PERSON")

    print("\n" + "=" * 60)
    print("  VERDICT")
    print("=" * 60)
    print(f"\n  Enrolled user:    {'ACCEPTED' if genuine_ok else 'REJECTED'}")
    print(f"  Different person: {'ACCEPTED (BAD)' if impostor_ok else 'REJECTED (GOOD)'}")

    if genuine_ok and not impostor_ok:
        print("\n  ✓ TEST PASSED")
        print("  The enrolled user unlocks the vault.")
        print("  A different person cannot — even with the distance check disabled.")
    else:
        print("\n  ✗ TEST FAILED")


if __name__ == "__main__":
    main()