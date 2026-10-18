"""
security_log.py
---------------
Writes security events as JSON Lines (one JSON object per line).
This is the contract with Pillar 2 (AI Guard): it reads these files as features.

Example line:
    {"ts": "2026-10-18T12:01:33.412+05:30", "event": "LOGIN_FAIL", "src_ip": "192.168.1.42",
     "src_port": 51522, "user": "bob", "session_id": null, "severity": "medium",
     "detail": "wrong password"}

RULE: never log keys, passwords or message text - only metadata.
"""

import json
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Every event name we use, with its default severity.
EVENTS = {
    # server side
    "LOGIN_OK": "low",
    "REGISTER_OK": "low",
    "LOGIN_FAIL": "medium",
    "LOGIN_LOCKOUT": "high",
    "FRAME_TOO_LARGE": "high",
    "MALFORMED_FRAME": "medium",
    "HANDSHAKE_TIMEOUT": "medium",   # connection never sent HELLO in time
    "BLOCKED_CONNECTION": "high",    # Pillar 3 blacklist dropped this IP
    "TLS_FAIL": "medium",
    # client side
    "SIG_FAIL": "high",              # handshake signature invalid -> likely MITM
    "IDENTITY_CHANGED": "high",      # peer's identity key differs from the saved one
    "TAG_FAIL": "high",              # AES-GCM tag mismatch -> tampering
    "REPLAY_OR_REORDER": "high",     # wrong sequence number -> replay
    "SESSION_CLOSED_TAG_FAILS": "high",
}


class SecurityLogger:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path

        # A dedicated Python logger per file, so lines never mix with normal logs.
        self.logger = logging.getLogger(f"security:{os.path.abspath(path)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        if not self.logger.handlers:
            # Rotate at 5 MB, keep 3 old files.
            handler = RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=3,
                                          encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)

    def event(self, event, src_ip=None, src_port=None, user=None,
              session_id=None, detail="", severity=None):
        """Write one security event. Returns the dict (handy for tests)."""
        record = {
            "ts": datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "event": event,
            "src_ip": src_ip,
            "src_port": src_port,
            "user": user,
            "session_id": session_id,
            "severity": severity or EVENTS.get(event, "medium"),
            "detail": detail,
        }
        self.logger.info(json.dumps(record))
        return record
