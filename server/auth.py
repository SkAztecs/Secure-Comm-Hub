"""
auth.py
-------
User accounts for the relay server.

    - Passwords are stored as Argon2id hashes (the current recommended password hash).
      The server NEVER stores the password itself.
    - Each account also stores the user's identity public key (Ed25519), so a
      stolen password alone can't be used to log in as that user from a new identity.
    - A rate limiter blocks an IP after too many failed logins (brute-force defence).

Database: SQLite file (default data/users.db). Table:
    users(username TEXT PRIMARY KEY, pw_hash TEXT, identity_pub TEXT, created_at TEXT)
"""

import os
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# One generic message for every login failure, so an attacker can't tell
# "user does not exist" apart from "wrong password".
GENERIC_FAILURE = "Invalid username or password"


class AuthError(Exception):
    """Login or registration refused. str(error) is safe to show to the client."""


class UserStore:
    def __init__(self, db_path: str = "data/users.db"):
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        # check_same_thread=False: the server calls us from a worker thread
        # (it holds a lock so only one thread uses the connection at a time).
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username     TEXT PRIMARY KEY,
                pw_hash      TEXT NOT NULL,
                identity_pub TEXT NOT NULL,
                created_at   TEXT NOT NULL
            )""")
        self.db.commit()

        # argon2-cffi defaults follow the RFC 9106 recommendations (Argon2id).
        self.hasher = PasswordHasher()
        # A dummy hash: verified for unknown users so their login takes the same
        # time as a real one (stops "timing" tricks that reveal valid usernames).
        self._dummy_hash = self.hasher.hash("dummy-password-for-timing")

    # ------------------------------------------------------------------
    def register(self, username: str, password: str, identity_pub_hex: str) -> None:
        if len(password) < 8:
            raise AuthError("Password must be at least 8 characters")

        exists = self.db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            raise AuthError(f"Username '{username}' is already registered")

        self.db.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            (username, self.hasher.hash(password), identity_pub_hex,
             datetime.now().isoformat(timespec="seconds")))
        self.db.commit()

    def login(self, username: str, password: str, identity_pub_hex: str) -> None:
        """Raises AuthError on any failure."""
        row = self.db.execute(
            "SELECT pw_hash, identity_pub FROM users WHERE username = ?", (username,)).fetchone()

        if row is None:
            # Burn the same time as a real check, then fail with the generic message.
            try:
                self.hasher.verify(self._dummy_hash, password)
            except VerificationError:
                pass
            raise AuthError(GENERIC_FAILURE)

        pw_hash, stored_identity = row
        try:
            self.hasher.verify(pw_hash, password)  # constant-time comparison inside
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            raise AuthError(GENERIC_FAILURE)

        if identity_pub_hex != stored_identity:
            raise AuthError("Identity key does not match this account "
                            "(log in from the device/keys folder you registered with)")

    def identity_of(self, username: str):
        row = self.db.execute(
            "SELECT identity_pub FROM users WHERE username = ?", (username,)).fetchone()
        return row[0] if row else None


class LoginRateLimiter:
    """
    Sliding-window limiter, per IP address:
        more than MAX_FAILURES failed logins within WINDOW_SECONDS
        -> that IP is locked out for LOCKOUT_SECONDS.
    """

    MAX_FAILURES = 5
    WINDOW_SECONDS = 60
    LOCKOUT_SECONDS = 60

    def __init__(self):
        self.failures = defaultdict(deque)  # ip -> timestamps of recent failures
        self.locked_until = {}              # ip -> time when the lockout ends

    def is_locked(self, ip: str) -> bool:
        until = self.locked_until.get(ip)
        if until and time.monotonic() < until:
            return True
        self.locked_until.pop(ip, None)
        return False

    def record_failure(self, ip: str) -> bool:
        """Record one failure. Returns True if this failure caused a lockout."""
        now = time.monotonic()
        recent = self.failures[ip]
        recent.append(now)
        # Forget failures older than the window.
        while recent and now - recent[0] > self.WINDOW_SECONDS:
            recent.popleft()

        if len(recent) >= self.MAX_FAILURES:
            self.locked_until[ip] = now + self.LOCKOUT_SECONDS
            recent.clear()
            return True
        return False

    def record_success(self, ip: str) -> None:
        self.failures.pop(ip, None)
