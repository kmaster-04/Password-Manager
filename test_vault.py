# tests/test_vault.py

import os
import pytest
import tempfile

from vault import (
    create_vault,
    load_vault,
    save_vault,
    add_credential,
    get_credential,
    update_credential,
    delete_credential,
    list_credentials,
    set_totp_secret,
)


@pytest.fixture
def temp_vault_path():
    # Create a temporary file path that doesn't exist yet
    fd, path = tempfile.mkstemp(suffix=".vault")
    os.close(fd)
    os.remove(path)  # We want the path to be free for creation
    yield path
    # Cleanup
    if os.path.exists(path):
        os.remove(path)


def test_create_and_load_empty_vault(temp_vault_path):
    master_pw = "testpassword123"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    assert creds == []


def test_wrong_password_fails_to_load(temp_vault_path):
    master_pw = "correctpassword"
    create_vault(temp_vault_path, master_pw)
    with pytest.raises(ValueError):
        load_vault(temp_vault_path, "wrongpassword")


def test_add_and_retrieve_credential(temp_vault_path):
    master_pw = "masterpw"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    add_credential(creds, "example.com", "alice", "secret1")
    save_vault(temp_vault_path, master_pw, creds)

    reloaded = load_vault(temp_vault_path, master_pw)
    matches = get_credential(reloaded, "example.com")
    assert len(matches) == 1
    assert matches[0]["username"] == "alice"
    assert matches[0]["password"] == "secret1"


def test_update_credential(temp_vault_path):
    master_pw = "masterpw"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    add_credential(creds, "example.com", "alice", "oldpass")
    save_vault(temp_vault_path, master_pw, creds)

    reloaded = load_vault(temp_vault_path, master_pw)
    updated = update_credential(reloaded, "example.com", password="newpass")
    assert updated is True
    save_vault(temp_vault_path, master_pw, reloaded)

    final = load_vault(temp_vault_path, master_pw)
    matches = get_credential(final, "example.com")
    assert matches[0]["password"] == "newpass"


def test_delete_credential(temp_vault_path):
    master_pw = "masterpw"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    add_credential(creds, "example.com", "alice", "pass1")
    add_credential(creds, "test.org", "bob", "pass2")
    save_vault(temp_vault_path, master_pw, creds)

    reloaded = load_vault(temp_vault_path, master_pw)
    deleted_count = delete_credential(reloaded, "example.com")
    assert deleted_count == 1
    save_vault(temp_vault_path, master_pw, reloaded)

    final = load_vault(temp_vault_path, master_pw)
    assert len(final) == 1
    assert final[0]["service"] == "test.org"


def test_list_credentials_does_not_include_passwords(temp_vault_path):
    master_pw = "masterpw"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    add_credential(creds, "example.com", "alice", "secret")
    save_vault(temp_vault_path, master_pw, creds)

    reloaded = load_vault(temp_vault_path, master_pw)
    listed = list_credentials(reloaded)
    assert listed == [("example.com", "alice")]
    assert not any("secret" in item for item in listed)


def test_add_credential_with_totp_secret(temp_vault_path):
    master_pw = "masterpw"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    add_credential(creds, "example.com", "alice", "secret", totp_secret="JBSWY3DPEHPK3PXP")
    save_vault(temp_vault_path, master_pw, creds)

    reloaded = load_vault(temp_vault_path, master_pw)
    matches = get_credential(reloaded, "example.com")
    assert matches[0]["totp_secret"] == "JBSWY3DPEHPK3PXP"


def test_add_credential_without_totp_secret_omits_field(temp_vault_path):
    master_pw = "masterpw"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    add_credential(creds, "example.com", "alice", "secret")
    save_vault(temp_vault_path, master_pw, creds)

    reloaded = load_vault(temp_vault_path, master_pw)
    assert "totp_secret" not in reloaded[0]


def test_set_totp_secret_updates_existing_credential(temp_vault_path):
    master_pw = "masterpw"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    add_credential(creds, "example.com", "alice", "secret")
    save_vault(temp_vault_path, master_pw, creds)

    reloaded = load_vault(temp_vault_path, master_pw)
    updated = set_totp_secret(reloaded, "example.com", "JBSWY3DPEHPK3PXP")
    assert updated is True
    save_vault(temp_vault_path, master_pw, reloaded)

    final = load_vault(temp_vault_path, master_pw)
    assert final[0]["totp_secret"] == "JBSWY3DPEHPK3PXP"


def test_set_totp_secret_returns_false_for_missing_service(temp_vault_path):
    master_pw = "masterpw"
    create_vault(temp_vault_path, master_pw)
    creds = load_vault(temp_vault_path, master_pw)
    add_credential(creds, "example.com", "alice", "secret")

    assert set_totp_secret(creds, "nonexistent.com", "JBSWY3DPEHPK3PXP") is False