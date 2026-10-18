"""
file_transfer.py
----------------
End-to-end encrypted file transfer.

A file is cut into 32 KB chunks. EVERY piece travels as a normal encrypted
packet (message type FILE_CHUNK = 0x11), so each chunk gets its own Double
Ratchet key, exactly like chat messages. The server only sees ciphertext.

Inside the encrypted packet, the plaintext is:
    <small JSON header> + b"\\n" + <raw bytes (chunks only)>

    {"kind": "start", "id": "...", "name": "notes.pdf", "size": 123456, "sha256": "...", "chunks": 4}
    {"kind": "chunk", "id": "...", "index": 0}  + 32 KB of file data
    ...
    {"kind": "end",   "id": "..."}

The receiver writes chunks to a temporary .part file, then checks the
SHA-256 of the whole file against the "start" header before keeping it.
"""

import hashlib
import json
import os
import re
import secrets
import time

CHUNK_SIZE = 32 * 1024            # 32 KB of file data per packet
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_ACTIVE_PER_SENDER = 4         # files one person may send to us at the same time
STALE_AFTER_SECONDS = 10 * 60     # unfinished transfers are cleaned up after 10 minutes


class FileTransferError(Exception):
    pass


def pack(header: dict, data: bytes = b"") -> bytes:
    return json.dumps(header).encode("utf-8") + b"\n" + data


def unpack(plaintext: bytes):
    """Split a piece into (header dict, data). Anything odd -> FileTransferError."""
    header_bytes, _, data = plaintext.partition(b"\n")
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise FileTransferError("Malformed file header")
    if not isinstance(header, dict):
        raise FileTransferError("File header must be a JSON object")
    return header, data


def as_int(value, field):
    """Read an integer field from the (untrusted) header."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise FileTransferError(f"File header field '{field}' must be a whole number")
    return value


def safe_filename(name: str) -> str:
    """
    Never trust a file name from the network: "../../windows/system32/x.dll"
    must not escape the downloads folder.
    """
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return name[:100] or "file"


def unique_path(folder: str, name: str) -> str:
    """downloads/notes.pdf -> downloads/notes (1).pdf if it already exists."""
    base, ext = os.path.splitext(name)
    path, counter = os.path.join(folder, name), 1
    while os.path.exists(path):
        path = os.path.join(folder, f"{base} ({counter}){ext}")
        counter += 1
    return path


# ----------------------------------------------------------------------
# Sending side
# ----------------------------------------------------------------------
def prepare_outgoing(path: str):
    """
    Read a file and yield the plaintext pieces to encrypt, in order.
    Returns (description dict, generator of plaintext bytes).
    """
    if not os.path.isfile(path):
        raise FileTransferError(f"File not found: {path}")
    size = os.path.getsize(path)
    if size > MAX_FILE_SIZE:
        raise FileTransferError(f"File too large ({size} bytes, limit {MAX_FILE_SIZE})")

    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)

    info = {
        "kind": "start",
        "id": secrets.token_hex(8),
        "name": os.path.basename(path),
        "size": size,
        "sha256": digest.hexdigest(),
        "chunks": max(1, -(-size // CHUNK_SIZE)),   # ceiling division
    }

    def pieces():
        yield pack(info)
        with open(path, "rb") as f:
            for index in range(info["chunks"]):
                yield pack({"kind": "chunk", "id": info["id"], "index": index}, f.read(CHUNK_SIZE))
        yield pack({"kind": "end", "id": info["id"]})

    return info, pieces()


# ----------------------------------------------------------------------
# Receiving side
# ----------------------------------------------------------------------
class IncomingFiles:
    """Keeps track of files currently being received, per sender."""

    def __init__(self, folder: str):
        self.folder = folder
        self.active = {}   # (sender, id) -> state dict

    def handle(self, sender: str, plaintext: bytes):
        """
        Process one decrypted piece. Returns a (kind, message) tuple for the UI:
            ("info", text) for progress, ("done", path) or ("failed", reason).
        Raises FileTransferError for malformed pieces (the caller reports it).
        """
        header, data = unpack(plaintext)
        kind, file_id = header.get("kind"), str(header.get("id"))[:64]
        key = (sender, file_id)
        self._remove_stale()

        if kind == "start":
            size = as_int(header.get("size", -1), "size")
            chunks = as_int(header.get("chunks", 0), "chunks")
            if not 0 <= size <= MAX_FILE_SIZE:
                return ("failed", f"refused file from {sender}: bad size {size}")
            if not 0 < chunks <= MAX_FILE_SIZE // CHUNK_SIZE + 1:
                return ("failed", f"refused file from {sender}: bad chunk count {chunks}")
            if key in self.active:
                return ("failed", f"refused file from {sender}: duplicate transfer id")
            if sum(1 for s, _ in self.active if s == sender) >= MAX_ACTIVE_PER_SENDER:
                return ("failed", f"refused file from {sender}: too many transfers at once")

            os.makedirs(self.folder, exist_ok=True)
            # The temporary file name is OUR random value, never the sender's id,
            # so a crafted id like "../../x" can't point outside the downloads folder.
            part_path = os.path.join(self.folder, f".incoming-{secrets.token_hex(16)}.part")
            self.active[key] = {
                "name": safe_filename(str(header.get("name", "file"))),
                "size": size, "sha256": str(header.get("sha256", "")),
                "chunks": chunks, "next": 0, "received": 0,
                "part": part_path, "handle": open(part_path, "wb"),
                "digest": hashlib.sha256(), "last_report": 0,
                "started": time.monotonic(),
            }
            state = self.active[key]
            return ("info", f"Receiving {state['name']} ({size:,} bytes) from {sender}...")

        state = self.active.get(key)
        if state is None:
            return ("failed", f"file piece from {sender} for an unknown transfer")

        if kind == "chunk":
            if header.get("index") != state["next"]:
                return self._fail(key, "chunk out of order")
            state["received"] += len(data)
            if state["received"] > state["size"]:
                return self._fail(key, "more data than announced")
            state["handle"].write(data)
            state["digest"].update(data)
            state["next"] += 1
            percent = 100 * state["received"] // max(state["size"], 1)
            if percent >= state["last_report"] + 25:
                state["last_report"] = percent - percent % 25
                return ("info", f"  {state['name']}: {state['last_report']}%")
            return None

        if kind == "end":
            del self.active[key]
            if state["next"] != state["chunks"] or state["received"] != state["size"]:
                self._discard(state)
                return ("failed", f"{state['name']} from {sender} is incomplete - discarded")
            if state["digest"].hexdigest() != state["sha256"]:
                self._discard(state)
                return ("failed", f"{state['name']} from {sender} FAILED the SHA-256 check - discarded")
            state["handle"].close()
            final_path = unique_path(self.folder, state["name"])
            os.replace(state["part"], final_path)
            return ("done", final_path)

        return ("failed", f"unknown file message '{kind}' from {sender}")

    def _fail(self, key, reason):
        state = self.active.pop(key)
        self._discard(state)
        return ("failed", f"{state['name']}: {reason} - discarded")

    @staticmethod
    def _discard(state):
        state["handle"].close()
        try:
            os.remove(state["part"])
        except OSError:
            pass

    def _remove_stale(self):
        """Drop transfers that never finished (sender vanished, or a flood of 'start's)."""
        now = time.monotonic()
        for key in [k for k, s in self.active.items() if now - s["started"] > STALE_AFTER_SECONDS]:
            self._discard(self.active.pop(key))

    def cancel_from(self, sender):
        """Called when a session with `sender` ends: clean up their unfinished files."""
        for key in [k for k in self.active if k[0] == sender]:
            self._discard(self.active.pop(key))
