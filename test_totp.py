# tests/test_totp.py
"""
Tests for the TOTP implementation.

The main correctness test uses the official RFC 6238 Appendix B test vectors.
These are the authoritative values from the standard, so passing them proves
the implementation is correct rather than merely plausible.
"""

import pytest
from totp import (
    generate_secret,
    generate_totp,
    verify_totp,
    seconds_remaining,
)


# --- RFC 6238 Appendix B test vectors ---
#
# The secret for all vectors is the ASCII string "12345678901234567890",
# which base32-encodes to "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".
#
# The reference values in the RFC are for 8-digit codes with SHA1.

RFC_SECRET_SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

RFC_VECTORS_SHA1 = [
    (59,          "94287082"),
    (1111111109,  "07081804"),
    (1111111111,  "14050471"),
    (1234567890,  "89005924"),
    (2000000000,  "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("timestamp,expected", RFC_VECTORS_SHA1)
def test_rfc6238_sha1_vectors(timestamp, expected):
    """Verify against the official RFC 6238 test vectors for SHA-1."""
    code = generate_totp(
        RFC_SECRET_SHA1,
        digits=8,
        period=30,
        algorithm="sha1",
        at_time=timestamp,
    )
    assert code == expected


def test_six_digit_code_is_six_chars():
    secret = generate_secret()
    code = generate_totp(secret, digits=6)
    assert len(code) == 6
    assert code.isdigit()


def test_eight_digit_code_is_eight_chars():
    secret = generate_secret()
    code = generate_totp(secret, digits=8)
    assert len(code) == 8
    assert code.isdigit()


def test_code_changes_with_time():
    """Codes for two different periods must differ."""
    secret = generate_secret()
    code_now = generate_totp(secret, at_time=1000)
    code_later = generate_totp(secret, at_time=2000)
    assert code_now != code_later


def test_code_is_stable_within_a_period():
    """Two timestamps in the same 30-second window give the same code."""
    secret = generate_secret()
    # Period 33 covers 990-1019, so both timestamps fall in the same window
    code_a = generate_totp(secret, at_time=1005)
    code_b = generate_totp(secret, at_time=1015)
    assert code_a == code_b


def test_verify_accepts_valid_code():
    secret = generate_secret()
    code = generate_totp(secret, at_time=1234567890)
    assert verify_totp(secret, code, at_time=1234567890)


def test_verify_rejects_wrong_code():
    secret = generate_secret()
    assert not verify_totp(secret, "000000", at_time=1234567890)


def test_verify_accepts_previous_period_within_window():
    """Clock skew: a code from the previous 30-second window is accepted."""
    secret = generate_secret()
    previous_code = generate_totp(secret, at_time=1234567890 - 30)
    assert verify_totp(secret, previous_code, at_time=1234567890, window=1)


def test_verify_rejects_previous_period_outside_window():
    """A code two periods old must be rejected when window is 1."""
    secret = generate_secret()
    old_code = generate_totp(secret, at_time=1234567890 - 60)
    assert not verify_totp(secret, old_code, at_time=1234567890, window=1)


def test_verify_rejects_malformed_input():
    secret = generate_secret()
    assert not verify_totp(secret, "abc123")
    assert not verify_totp(secret, "12345")
    assert not verify_totp(secret, "1234567")


def test_secret_generation_is_unique():
    secrets = {generate_secret() for _ in range(50)}
    assert len(secrets) == 50


def test_secret_is_valid_base32():
    import base64
    secret = generate_secret()
    padded = secret + "=" * ((-len(secret)) % 8)
    raw = base64.b32decode(padded)
    assert len(raw) == 20


def test_seconds_remaining_in_range():
    remaining = seconds_remaining(period=30)
    assert 1 <= remaining <= 30


def test_invalid_digit_count_rejected():
    secret = generate_secret()
    with pytest.raises(ValueError):
        generate_totp(secret, digits=4)
    with pytest.raises(ValueError):
        generate_totp(secret, digits=12)


def test_invalid_secret_rejected():
    with pytest.raises(ValueError):
        generate_totp("not a valid base32 secret!!", at_time=1000)