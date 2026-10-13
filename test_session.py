# tests/test_session.py

import time
import pytest
from session import VaultSession

def test_session_initially_unlocked():
    s = VaultSession("vault.vault", "masterpw", [{"service": "test.com", "username": "alice", "password": "secret"}])
    assert not s.is_locked()
    assert s.credentials[0]["username"] == "alice"
    # Clean up
    s.lock()

def test_lock_wipes_data():
    s = VaultSession("vault.vault", "masterpw", [{"service": "test.com", "username": "alice", "password": "secret"}])
    s.lock()
    assert s.is_locked()
    assert s.master_password == ""
    assert s.credentials == []

def test_touch_resets_timer():
    # Use a very short timeout for testing
    s = VaultSession("vault.vault", "masterpw", [], timeout_seconds=1)
    time.sleep(0.5)
    s.touch()  # reset timer
    time.sleep(0.6)  # total elapsed >1s since last touch, but timer restarted
    assert not s.is_locked()
    s.lock()

def test_auto_lock_triggers():
    s = VaultSession("vault.vault", "masterpw", [], timeout_seconds=1)
    time.sleep(1.5)
    assert s.is_locked()