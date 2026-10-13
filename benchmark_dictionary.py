# benchmark_dictionary.py
import os
import time
from vault import create_vault, load_vault

def dictionary_attack(vault_path, master_password, wordlist_path):
    """
    Simulate a dictionary attack: try each password from the wordlist against the vault.
    Returns (attempts, successes, elapsed_seconds).
    """
       # Remove any leftover test vault from a previous run
    if os.path.exists(vault_path):
        os.remove(vault_path)

    # Create a test vault with a strong master password (NOT in the wordlist)
    create_vault(vault_path, master_password)

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(passwords)} candidate passwords.")
    print(f"Vault created with a strong master password (not in wordlist).")
    print(f"Starting dictionary attack...\n")

    start = time.perf_counter()
    successes = 0
    for i, candidate in enumerate(passwords):
        try:
            load_vault(vault_path, candidate)
            print(f"[!] SUCCESS with password: {candidate}")
            successes += 1
        except Exception:
            pass
        if (i + 1) % 10 == 0:
            elapsed = time.perf_counter() - start
            print(f"Attempted {i+1}/{len(passwords)} | elapsed: {elapsed:.1f}s")

    elapsed = time.perf_counter() - start

    print("\n--- Dictionary Attack Results ---")
    print(f"Total attempts: {len(passwords)}")
    print(f"Successful decryptions: {successes}")
    print(f"Elapsed time: {elapsed:.2f}s")
    print(f"Average per attempt: {elapsed/len(passwords):.3f}s")
    print(f"Success criterion (0 successes): {'PASS' if successes == 0 else 'FAIL'}")

    # Extrapolation
    if len(passwords) > 0:
        extrapolated_full = (elapsed / len(passwords)) * 10000
        print(f"\nExtrapolated time for full 10,000-entry list: {extrapolated_full/60:.1f} minutes")

if __name__ == "__main__":
    dictionary_attack(
        vault_path="test_vault.vault",
        master_password="xK9#mP2$vL7@qR4!bT6",   # strong, not in wordlist
        wordlist_path="rockyou_sample.txt"
    )