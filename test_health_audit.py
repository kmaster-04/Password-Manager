# tests/test_health_audit.py

import os
import tempfile

from health_audit import (
    estimate_entropy,
    load_common_passwords,
    audit_vault,
)


def test_entropy_of_empty_password_is_zero():
    assert estimate_entropy("") == 0.0


def test_entropy_grows_with_length():
    short = estimate_entropy("abc")
    long = estimate_entropy("abcdefghijklmnop")
    assert long > short


def test_entropy_grows_with_character_classes():
    lower = estimate_entropy("abcdefghij")
    mixed = estimate_entropy("aBcD3fG!jK")
    assert mixed > lower


def test_load_common_passwords_reads_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        with open(path, "w") as f:
            f.write("password\n123456\nqwerty\n")
        common = load_common_passwords(path)
        assert "password" in common
        assert "123456" in common
        assert "qwerty" in common
        assert len(common) == 3
    finally:
        os.remove(path)


def test_load_common_passwords_handles_missing_file():
    common = load_common_passwords("/nonexistent/path.txt")
    assert common == set()


def test_audit_detects_weak_password():
    creds = [{"service": "a.com", "username": "u", "password": "abc"}]
    report = audit_vault(creds)
    assert len(report["weak"]) == 1
    assert report["weak"][0][0] == "a.com"


def test_audit_detects_common_password():
    creds = [{"service": "a.com", "username": "u", "password": "password123"}]
    report = audit_vault(creds, common_passwords={"password123"})
    reasons = report["weak"][0][1]
    assert any("common" in r for r in reasons)


def test_audit_detects_reused_password():
    creds = [
        {"service": "a.com", "username": "u", "password": "SamePassword123!Extra"},
        {"service": "b.com", "username": "u", "password": "SamePassword123!Extra"},
    ]
    report = audit_vault(creds)
    assert len(report["reused"]) == 1
    services = list(report["reused"].values())[0]
    assert set(services) == {"a.com", "b.com"}


def test_audit_does_not_flag_unique_password_as_reused():
    creds = [
        {"service": "a.com", "username": "u", "password": "UniqueOne123!LongEnough"},
        {"service": "b.com", "username": "u", "password": "UniqueTwo456!LongEnough"},
    ]
    report = audit_vault(creds)
    assert report["reused"] == {}


def test_audit_flags_missing_totp():
    creds = [
        {"service": "a.com", "username": "u", "password": "StrongPassword123!"},
        {"service": "b.com", "username": "u", "password": "OtherPassword456!",
         "totp_secret": "JBSWY3DPEHPK3PXP"},
    ]
    report = audit_vault(creds)
    assert "a.com" in report["missing_totp"]
    assert "b.com" not in report["missing_totp"]


def test_audit_empty_vault():
    report = audit_vault([])
    assert report["total"] == 0
    assert report["weak"] == []
    assert report["reused"] == {}
    assert report["missing_totp"] == []