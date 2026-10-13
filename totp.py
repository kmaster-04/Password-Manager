# totp.py
"""
Time-based One-Time Password (TOTP) implementation.

Implements RFC 6238 from scratch using only the Python standard library.
No external TOTP libraries are used — every step is written here so the
algorithm is transparent and independently verifiable.

References:
    RFC 4226 — HMAC-Based One-Time Password (HOTP) Algorithm
    RFC 6238 — TOTP: Time-Based One-Time Password Algorithm
"""

import base64
import hashlib
import hmac
import os
import struct
import time


DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_ALGORITHM = "sha1"


def generate_secret(length_bytes: int = 20) -> str:
    """
    Generate a new random TOTP secret, returned as a base32 string.

    A length of 20 bytes (160 bits) matches the RFC 4226 recommendation
    for HMAC-SHA1 secrets and produces a 32-character base32 string.
    """
    raw = os.urandom(length_bytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """
    Decode a base32-encoded secret into raw bytes.

    Base32 strings are case-insensitive and may or may not include padding.
    This normalises both cases before decoding.
    """
    normalised = secret.strip().replace(" ", "").upper()
    # Restore any missing padding (base32 requires length multiple of 8)
    padding_needed = (-len(normalised)) % 8
    normalised += "=" * padding_needed
    try:
        return base64.b32decode(normalised)
    except Exception as exc:
        raise ValueError(f"Invalid base32 secret: {exc}")


def _hotp(key: bytes, counter: int, digits: int, algorithm: str) -> str:
    """
    Compute an HOTP value for the given counter (RFC 4226 section 5.3).

    Steps:
      1. Convert the counter to an 8-byte big-endian integer.
      2. HMAC the counter with the secret key.
      3. Dynamic truncation: use the low nibble of the last byte as an
         offset, take 4 bytes from that offset, mask the top bit.
      4. Reduce modulo 10^digits and zero-pad to the requested length.
    """
    # Step 1: counter as 8-byte big-endian
    counter_bytes = struct.pack(">Q", counter)

    # Step 2: HMAC
    digestmod = {
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }[algorithm]
    mac = hmac.new(key, counter_bytes, digestmod).digest()

    # Step 3: dynamic truncation
    offset = mac[-1] & 0x0F
    binary = (
        ((mac[offset] & 0x7F) << 24)
        | ((mac[offset + 1] & 0xFF) << 16)
        | ((mac[offset + 2] & 0xFF) << 8)
        | (mac[offset + 3] & 0xFF)
    )

    # Step 4: reduce and pad
    code = binary % (10 ** digits)
    return str(code).zfill(digits)


def generate_totp(
    secret: str,
    digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD,
    algorithm: str = DEFAULT_ALGORITHM,
    at_time: float | None = None,
) -> str:
    """
    Generate the current TOTP code for a base32-encoded secret.

    Args:
        secret: Base32-encoded shared secret.
        digits: Number of digits in the code (usually 6 or 8).
        period: Time step in seconds (usually 30).
        algorithm: HMAC hash — 'sha1', 'sha256', or 'sha512'.
        at_time: Unix timestamp to use (defaults to now; useful for tests).

    Returns:
        The zero-padded TOTP code as a string.
    """
    if digits < 6 or digits > 10:
        raise ValueError("digits must be between 6 and 10")
    if period < 1:
        raise ValueError("period must be at least 1 second")

    key = _decode_secret(secret)
    timestamp = time.time() if at_time is None else at_time
    counter = int(timestamp // period)
    return _hotp(key, counter, digits, algorithm)


def verify_totp(
    secret: str,
    code: str,
    digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD,
    algorithm: str = DEFAULT_ALGORITHM,
    window: int = 1,
    at_time: float | None = None,
) -> bool:
    """
    Verify a TOTP code, allowing for clock skew.

    A window of 1 checks the current period plus the previous and next,
    accommodating a ±30-second drift between the device and the server.
    This mirrors standard practice in production authenticators.
    """
    if not code.isdigit() or len(code) != digits:
        return False

    timestamp = time.time() if at_time is None else at_time
    counter = int(timestamp // period)
    key = _decode_secret(secret)

    for offset in range(-window, window + 1):
        expected = _hotp(key, counter + offset, digits, algorithm)
        # Constant-time comparison avoids timing side channels
        if hmac.compare_digest(expected, code):
            return True
    return False


def seconds_remaining(period: int = DEFAULT_PERIOD) -> int:
    """Return seconds until the current TOTP code expires."""
    return period - int(time.time() % period)


# --- CLI for manual testing ---

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python totp.py new            Generate a new secret")
        print("  python totp.py show <SECRET>  Show current code for a secret")
        print("  python totp.py watch <SECRET> Continuously display the code")
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "new":
        secret = generate_secret()
        print(f"New TOTP secret: {secret}")
        print(f"Current code:    {generate_totp(secret)}")
        print(f"Expires in:      {seconds_remaining()} seconds")

    elif command == "show" and len(sys.argv) == 3:
        secret = sys.argv[2]
        code = generate_totp(secret)
        print(f"Code: {code}")
        print(f"Expires in {seconds_remaining()} seconds")

    elif command == "watch" and len(sys.argv) == 3:
        secret = sys.argv[2]
        try:
            while True:
                code = generate_totp(secret)
                remaining = seconds_remaining()
                print(f"\rCode: {code}   Expires in {remaining:2d}s", end="", flush=True)
                time.sleep(1)
        except KeyboardInterrupt:
            print()

    else:
        print("Unknown command. Run without arguments for usage.")