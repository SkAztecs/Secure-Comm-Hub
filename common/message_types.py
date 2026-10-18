"""
message_types.py
----------------
All message type codes used by the protocol, in ONE place.

These match the "Message types" table in the protocol spec.
Every file imports from here so a code is never typed twice.
"""

# Protocol version. Goes into byte 0 of every encrypted packet.
PROTOCOL_VERSION = 0x01

# ---- Message type codes (1 byte each) ----
HELLO = 0x01        # client -> server : "my name is alice"
KEY_INIT = 0x02     # client -> client : start of key exchange (my ephemeral public key)
KEY_RESP = 0x03     # client -> client : reply to key exchange (my ephemeral public key)
CHAT = 0x10         # client -> client : an encrypted chat message
FILE_CHUNK = 0x11   # client -> client : encrypted file piece (Phase 3)
REKEY = 0x20        # client -> client : ask for a fresh handshake (Phase 2)
ACK = 0x30          # client -> client : acknowledgement
ERROR = 0x7F        # server -> client : something went wrong (user offline, bad frame...)

# Names are handy for the JSON envelope and for logs.
# We send the NAME ("CHAT") in the envelope so the JSON stays human-readable.
CODE_TO_NAME = {
    HELLO: "HELLO",
    KEY_INIT: "KEY_INIT",
    KEY_RESP: "KEY_RESP",
    CHAT: "CHAT",
    FILE_CHUNK: "FILE_CHUNK",
    REKEY: "REKEY",
    ACK: "ACK",
    ERROR: "ERROR",
}

# Reverse lookup: "CHAT" -> 0x10
NAME_TO_CODE = {name: code for code, name in CODE_TO_NAME.items()}
