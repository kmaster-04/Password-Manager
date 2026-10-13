# tests/test_password_gen.py

import pytest
from password_gen import generate_password

def test_default_length():
    pwd = generate_password()
    assert len(pwd) == 20

def test_custom_length():
    pwd = generate_password(length=12)
    assert len(pwd) == 12

def test_contains_required_character_sets():
    pwd = generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in "!@#$%^&*()-_=+[]{};:,.<>?/\\|`~" for c in pwd)

def test_only_lowercase():
    pwd = generate_password(length=10, use_upper=False, use_lower=True, use_digits=False, use_symbols=False)
    assert all(c.islower() for c in pwd)

def test_no_charset_selected_raises_error():
    with pytest.raises(ValueError):
        generate_password(length=8, use_upper=False, use_lower=False, use_digits=False, use_symbols=False)

def test_length_zero_raises_error():
    with pytest.raises(ValueError):
        generate_password(length=0)

def test_generated_passwords_are_unique():
    pwd1 = generate_password()
    pwd2 = generate_password()
    assert pwd1 != pwd2