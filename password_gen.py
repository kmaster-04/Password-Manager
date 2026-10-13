# password_gen.py

import secrets
import string

def generate_password(length=20, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    """
    Generate a cryptographically secure random password.

    Args:
        length: Desired password length (default 20).
        use_upper: Include uppercase letters.
        use_lower: Include lowercase letters.
        use_digits: Include digits.
        use_symbols: Include punctuation symbols.

    Returns:
        A string containing the generated password.

    Raises:
        ValueError: If no character set is selected or length is less than 1.
    """
    if length < 1:
        raise ValueError("Password length must be at least 1.")

    charset = ""
    if use_upper:
        charset += string.ascii_uppercase
    if use_lower:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += string.punctuation

    if not charset:
        raise ValueError("At least one character set must be selected.")

    # Ensure at least one character from each selected set (if possible)
    password_chars = []
    if use_upper:
        password_chars.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        password_chars.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        password_chars.append(secrets.choice(string.digits))
    if use_symbols:
        password_chars.append(secrets.choice(string.punctuation))

    # Fill the rest with random choices from the full charset
    remaining_length = length - len(password_chars)
    for _ in range(max(0, remaining_length)):
        password_chars.append(secrets.choice(charset))

    # Shuffle the resulting list to avoid predictable ordering
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)