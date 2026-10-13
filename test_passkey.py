import os
import tempfile
import pytest

import passkey


@pytest.fixture
def temp_paths():
    fd, vault_path = tempfile.mkstemp(suffix=".vault")
    os.close(fd)
    os.remove(vault_path)
    fd, key_path = tempfile.mkstemp(suffix=".pem")
    os.close(fd)
    os.remove(key_path)
    yield vault_path, key_path
    for p in (vault_path, key_path, vault_path + ".passkey"):
        if os.path.exists(p):
            os.remove(p)


def test_enroll_creates_files(temp_paths):
    vault_path, key_path = temp_paths
    enrollment_path = passkey.enroll(vault_path, "masterpw", key_path)
    assert os.path.exists(enrollment_path)
    assert os.path.exists(key_path)


def test_unlock_recovers_master_password(temp_paths):
    vault_path, key_path = temp_paths
    passkey.enroll(vault_path, "masterpw", key_path)
    assert passkey.unlock_with_passkey(vault_path, key_path) == "masterpw"


def test_unlock_fails_with_wrong_device_key(temp_paths):
    vault_path, key_path = temp_paths
    passkey.enroll(vault_path, "masterpw", key_path)

    other_key = passkey.generate_device_keypair()
    passkey.save_private_key(other_key, key_path)

    with pytest.raises(ValueError):
        passkey.unlock_with_passkey(vault_path, key_path)


def test_unlock_fails_without_enrollment(temp_paths):
    vault_path, key_path = temp_paths
    with pytest.raises(FileNotFoundError):
        passkey.unlock_with_passkey(vault_path, key_path)


def test_unlock_fails_without_device_key(temp_paths):
    vault_path, key_path = temp_paths
    passkey.enroll(vault_path, "masterpw", key_path)
    os.remove(key_path)
    with pytest.raises(FileNotFoundError):
        passkey.unlock_with_passkey(vault_path, key_path)


def test_verify_device_accepts_matching_key(temp_paths):
    vault_path, key_path = temp_paths
    passkey.enroll(vault_path, "masterpw", key_path)
    enrollment = passkey._load_enrollment(vault_path + ".passkey")
    private_key = passkey.load_private_key(key_path)
    assert passkey.verify_device(enrollment, private_key) is True


def test_verify_device_rejects_mismatched_key(temp_paths):
    vault_path, key_path = temp_paths
    passkey.enroll(vault_path, "masterpw", key_path)
    enrollment = passkey._load_enrollment(vault_path + ".passkey")
    other_key = passkey.generate_device_keypair()
    assert passkey.verify_device(enrollment, other_key) is False


def test_enrollment_file_does_not_contain_master_password(temp_paths):
    vault_path, key_path = temp_paths
    passkey.enroll(vault_path, "SuperSecretMasterPw", key_path)
    with open(vault_path + ".passkey", "r") as f:
        contents = f.read()
    assert "SuperSecretMasterPw" not in contents