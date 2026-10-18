"""
firewall_hook.py
----------------
Contract 2 with Pillar 3 (Firewall): the relay server asks "is this IP blocked?"
FIRST THING for every new connection - before TLS, before HELLO, before any crypto.

Simplest shared format (agree with the Pillar 3 teammate, change if needed):
    a text file, one IP per line, '#' starts a comment.
    Default path: data/blacklist.txt

Pillar 3 writes the file; we re-read it whenever its modification time changes,
so a newly blocked IP is refused on its very next connection attempt.
"""

import os


class FirewallHook:
    def __init__(self, blacklist_path: str = "data/blacklist.txt"):
        self.path = blacklist_path
        self._blocked = set()
        self._last_mtime = None

    def _reload_if_changed(self):
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            # No file yet = nobody blocked.
            self._blocked = set()
            self._last_mtime = None
            return

        if mtime != self._last_mtime:
            with open(self.path, encoding="utf-8") as f:
                lines = (line.split("#", 1)[0].strip() for line in f)
                self._blocked = {line for line in lines if line}
            self._last_mtime = mtime

    def is_blocked(self, ip: str) -> bool:
        self._reload_if_changed()
        return ip in self._blocked
