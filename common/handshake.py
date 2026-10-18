"""
handshake.py
------------
Exactly WHAT gets signed during the key exchange.

A signature only helps if it covers the right things. We sign a "transcript":

    KEY_INIT  signed by the initiator over:
        "KEY_INIT|v2|" + initiator + "|" + responder + "|" + every field the initiator sent

    KEY_RESP  signed by the responder over:
        "KEY_RESP|v2|" + initiator + "|" + responder + "|"
                       + every field of KEY_INIT + every field of KEY_RESP

Fields (bytes):
    KEY_INIT:  pub      initiator's X25519 ephemeral key (32 B)
               kem_pub  initiator's ML-KEM-768 public key (1184 B)   - post-quantum mode only
               ts       time the handshake started (8 B, Unix seconds) - so an OLD signed
                        KEY_INIT replayed later is refused (freshness)
    KEY_RESP:  pub      responder's X25519 ephemeral key (32 B)
               kem_ct   ML-KEM ciphertext for the initiator (1088 B)  - post-quantum mode only

Why the names?   So a signed KEY_INIT meant for bob can't be replayed to carol.
Why all the fields?
    - Swapping any key breaks the signature (man-in-the-middle).
    - REMOVING kem_pub also breaks it, so an attacker can't silently downgrade
      a post-quantum handshake to a classic one (a "downgrade attack").
Why both messages in KEY_RESP?   So the reply is tied to THIS handshake, not an old one.

Usernames can only contain letters, digits, _ and - (enforced by the server),
so the "|" separator can never appear inside a name.
"""

import struct


def _encode_fields(fields: dict) -> bytes:
    """Unambiguous encoding: for each field (sorted by name): name | 4-byte length | value."""
    out = b""
    for name in sorted(fields):
        value = fields[name]
        out += name.encode() + b"|" + struct.pack(">I", len(value)) + value
    return out


def init_transcript(initiator: str, responder: str, init_fields: dict) -> bytes:
    return (b"KEY_INIT|v2|" + initiator.encode() + b"|" + responder.encode() + b"|"
            + _encode_fields(init_fields))


def resp_transcript(initiator: str, responder: str, init_fields: dict, resp_fields: dict) -> bytes:
    return (b"KEY_RESP|v2|" + initiator.encode() + b"|" + responder.encode() + b"|"
            + _encode_fields(init_fields) + b"||" + _encode_fields(resp_fields))


# Names of the binary fields each handshake message may carry (base64 in the envelope).
INIT_FIELDS = ("pub", "kem_pub", "ts")

# A KEY_INIT older/newer than this (seconds) is refused. Allows for laptop clocks
# being a few minutes apart.
MAX_CLOCK_SKEW = 300
RESP_FIELDS = ("pub", "kem_ct")
