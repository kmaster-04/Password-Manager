# session.py

import time
import threading

class VaultSession:
    """
    Manages the unlocked vault in memory.

    The session holds the master password (or derived key) and the decrypted
    credential list. It supports automatic locking after a period of inactivity,
    and explicit wiping of sensitive data on lock.
    """

    def __init__(self, vault_path: str, master_password: str, credentials: list, timeout_seconds: int = 300):
        """
        Initialize a session.

        Args:
            vault_path: Path to the vault file (used for saving later).
            master_password: The master password (kept only in memory).
            credentials: The decrypted list of credential dictionaries.
            timeout_seconds: Auto-lock timeout in seconds (default 300 = 5 minutes).
        """
        self.vault_path = vault_path
        self.master_password = master_password
        self.credentials = credentials
        self.timeout_seconds = timeout_seconds
        self._last_activity = time.time()
        self._lock_timer = None
        self._is_locked = False
        self._start_timer()

    def _start_timer(self):
        """Start or restart the inactivity timer."""
        if self._lock_timer:
            self._lock_timer.cancel()
        self._lock_timer = threading.Timer(self.timeout_seconds, self.lock)
        self._lock_timer.daemon = True
        self._lock_timer.start()

    def touch(self):
        """Record user activity and restart the timer."""
        if not self._is_locked:
            self._last_activity = time.time()
            self._start_timer()

    def lock(self):
        """
        Lock the session: wipe sensitive data from memory and mark as locked.

        After locking, the session cannot be used; a new session must be created
        by re-entering the master password.
        """
        if self._is_locked:
            return

        # Wipe master password string
        if isinstance(self.master_password, str):
            # Strings are immutable, but we can overwrite the reference
            self.master_password = ""
        # Wipe credentials list
        if self.credentials:
            for i in range(len(self.credentials)):
                self.credentials[i] = None
            self.credentials = []

        self._is_locked = True
        if self._lock_timer:
            self._lock_timer.cancel()

    def is_locked(self):
        """Return True if the session is locked."""
        return self._is_locked

    def __del__(self):
        """Ensure timer is cancelled when object is destroyed."""
        if self._lock_timer:
            self._lock_timer.cancel()