"""
handshake.py
------------
Exactly WHAT gets signed during the key exchange.

A signature only helps if it covers the right things. We sign a "transcript":

    KEY_INIT  signed by the initiator over:
        "KEY_INIT|v1|" + initiator name + "|" + responder name + "|" + initiator ephemeral key

    KEY_RESP  signed by the responder over:
        "KEY_RESP|v1|" + initiator name + "|" + responder name + "|"
                       + initiator ephemeral key + responder ephemeral key

Why the names?   So a signed KEY_INIT meant for bob can't be replayed to carol.
Why both keys in KEY_RESP?   So the reply is tied to THIS handshake, not an old one.
Why "v1"?   So a future protocol version can't be confused with this one.

Usernames can only contain letters, digits, _ and - (enforced by the server),
so the "|" separator can never appear inside a name.
"""


def init_transcript(initiator: str, responder: str, initiator_eph: bytes) -> bytes:
    return b"KEY_INIT|v1|" + initiator.encode() + b"|" + responder.encode() + b"|" + initiator_eph


def resp_transcript(initiator: str, responder: str,
                    initiator_eph: bytes, responder_eph: bytes) -> bytes:
    return (b"KEY_RESP|v1|" + initiator.encode() + b"|" + responder.encode() + b"|"
            + initiator_eph + responder_eph)
