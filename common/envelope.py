"""
envelope.py
-----------
The OUTER layer of every frame: a small JSON "envelope".

The relay server CAN read the envelope (it needs `to` to route the message),
but the actual chat text is inside `packet`, which is AES-GCM encrypted
with a key the server never has.

Example envelope:
    {"from": "alice", "to": "bob", "type": "CHAT", "packet": "<base64 bytes>"}

Handshake envelopes carry a public key instead of a packet:
    {"from": "alice", "to": "bob", "type": "KEY_INIT", "pub": "<base64 32 bytes>"}
"""

import base64
import json


class EnvelopeError(Exception):
    """Raised when an envelope is not valid JSON or is missing fields."""


def b64encode(data: bytes) -> str:
    """bytes -> text, so binary data can live inside JSON."""
    return base64.b64encode(data).decode("ascii")


def b64decode(text: str) -> bytes:
    """text -> bytes (reverse of b64encode)."""
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        raise EnvelopeError("Invalid base64 data")


def make_envelope(msg_type: str, sender: str, to: str = None, **fields) -> bytes:
    """
    Build an envelope and return it as UTF-8 JSON bytes (ready for send_frame).
    Extra keyword fields (packet=..., pub=..., text=...) are added as-is.
    """
    envelope = {"type": msg_type, "from": sender}
    if to is not None:
        envelope["to"] = to
    envelope.update(fields)
    return json.dumps(envelope).encode("utf-8")


def parse_envelope(data: bytes) -> dict:
    """JSON bytes -> dict. Checks that the basic fields exist."""
    try:
        envelope = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise EnvelopeError("MALFORMED_FRAME: not valid JSON")

    if not isinstance(envelope, dict) or "type" not in envelope:
        raise EnvelopeError("MALFORMED_FRAME: missing 'type'")

    return envelope
