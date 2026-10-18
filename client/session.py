"""
session.py
----------
One Session = one encrypted conversation with ONE peer.

Phase 3 version. A session now has two parts:

1. The HANDSHAKE (once per session, signed by client_core.py):

    Alice (initiator)                               Bob (responder)
    -----------------                               ---------------
    init_fields():
      X25519 ephemeral key pair
      ML-KEM-768 key pair            KEY_INIT
                                     {pub, kem_pub} ---------->  respond(init_fields):
                                                                   X25519 ephemeral key pair
                                                                   x  = X25519(priv_B, pub_A)
                                                                   pq, kem_ct = ML-KEM.encapsulate(kem_pub)
                                     KEY_RESP
                                     <---------- {pub, kem_ct}
    finish(resp_fields):
      x  = X25519(priv_A, pub_B)
      pq = ML-KEM.decapsulate(kem_ct)
    root key = HKDF(x || pq)                                    root key = HKDF(x || pq)

   Hybrid: an attacker must break BOTH X25519 and ML-KEM to learn the root key.
   Classic mode (--no-pq, or an old cryptography library): pq = b"" (X25519 only).

2. The DOUBLE RATCHET (common/ratchet.py) starts from the root key and gives
   every single message its own key.

The --insecure demo mode keeps the Phase 1 design on purpose: one static key per
direction, AES-CTR with no integrity, no replay check, no ratchet, no post-quantum.
"""

import struct
import time

from cryptography.exceptions import InvalidTag

from common import crypto_utils
from common.message_types import CHAT
from common.packet import (PacketError, build_packet, build_ratchet_packet, open_packet,
                           open_ratchet_packet)
from common.ratchet import DoubleRatchet, RatchetError

SUITE_HYBRID = "X25519 + ML-KEM-768 (post-quantum hybrid)"
SUITE_CLASSIC = "X25519 (classic)"


class SessionError(Exception):
    """Replays, out-of-order packets, using a session too early, handshake problems."""


class Session:
    # Rekey rules: a full new handshake after this many messages OR this many seconds.
    # (The Double Ratchet already renews keys constantly; this also refreshes the
    #  post-quantum secret, which the ratchet itself doesn't.)
    MAX_MESSAGES = 1000
    MAX_AGE_SECONDS = 60 * 60

    # Close the session after this many tampered packets.
    MAX_TAG_FAILURES = 3

    def __init__(self, peer: str, is_initiator: bool, insecure: bool = False, pq: bool = True):
        self.peer = peer
        self.is_initiator = is_initiator
        self.insecure = insecure                    # DEMO ONLY
        self.pq = pq and crypto_utils.HAS_MLKEM and not insecure
        self.suite = None                           # set when the handshake finishes

        # Fresh X25519 key pair for THIS session only.
        self._private_key, self.my_public = crypto_utils.generate_x25519_keypair()
        self._kem_private = None
        self.peer_public = None
        self.peer_identity = None                   # peer's Ed25519 key (set by the client)
        self._init_fields = None                    # kept so the initiator can finish()

        self.ratchet = None                         # secure mode (v2 packets)
        self.send_key = None                        # insecure demo mode (v1 packets)
        self.recv_key = None
        self.send_seq = 0                           # messages sent (for rekey + v1 nonces)
        self.recv_seq = 0                           # v1 only: next expected seq

        self.created_at = time.monotonic()
        self.tag_failures = 0

    @property
    def ready(self) -> bool:
        return self.ratchet is not None or self.send_key is not None

    # ==================================================================
    # Handshake
    # ==================================================================
    def init_fields(self) -> dict:
        """INITIATOR: the fields for KEY_INIT."""
        fields = {"pub": self.my_public, "ts": struct.pack(">Q", int(time.time()))}
        if self.pq:
            self._kem_private, fields["kem_pub"] = crypto_utils.generate_mlkem_keypair()
        self._init_fields = fields
        return fields

    def respond(self, init_fields: dict) -> dict:
        """RESPONDER: process KEY_INIT, return the fields for KEY_RESP. Keys are ready after this."""
        their_pub = init_fields.get("pub", b"")
        if len(their_pub) != 32:
            raise SessionError("Peer public key must be 32 bytes")

        resp_fields = {"pub": self.my_public}
        pq_secret = b""
        if "kem_pub" in init_fields and not self.insecure:
            if not crypto_utils.HAS_MLKEM:
                raise SessionError("Peer uses post-quantum mode but this machine's 'cryptography' "
                                   "is older than 47.0. Run: pip install -U cryptography")
            pq_secret, resp_fields["kem_ct"] = crypto_utils.mlkem_encapsulate(init_fields["kem_pub"])

        x25519_secret = crypto_utils.compute_shared_secret(self._private_key, their_pub)
        self.peer_public = their_pub
        self._derive(x25519_secret, pq_secret, initiator_pub=their_pub, responder_pub=self.my_public,
                     pq_used="kem_ct" in resp_fields)
        return resp_fields

    def finish(self, resp_fields: dict) -> None:
        """INITIATOR: process KEY_RESP. Keys are ready after this."""
        their_pub = resp_fields.get("pub", b"")
        if len(their_pub) != 32:
            raise SessionError("Peer public key must be 32 bytes")

        pq_secret = b""
        if self._kem_private is not None:
            if "kem_ct" not in resp_fields:
                # We offered post-quantum and the reply has none: refuse rather than downgrade.
                raise SessionError("Peer did not complete the post-quantum key exchange")
            pq_secret = crypto_utils.mlkem_decapsulate(self._kem_private, resp_fields["kem_ct"])
            self._kem_private = None

        x25519_secret = crypto_utils.compute_shared_secret(self._private_key, their_pub)
        self.peer_public = their_pub
        self._derive(x25519_secret, pq_secret, initiator_pub=self.my_public, responder_pub=their_pub,
                     pq_used=bool(pq_secret))

    def _derive(self, x25519_secret, pq_secret, initiator_pub, responder_pub, pq_used):
        if self.insecure:
            # Phase 1 style: two static keys, no ratchet (demo mode only).
            key_i2r, key_r2i = crypto_utils.derive_session_keys(x25519_secret, initiator_pub,
                                                                responder_pub)
            self.send_key, self.recv_key = (key_i2r, key_r2i) if self.is_initiator else (key_r2i, key_i2r)
            self.suite = "INSECURE demo (static key, AES-CTR)"
        else:
            root_key, responder_chain = crypto_utils.derive_root_material(
                x25519_secret, pq_secret, initiator_pub, responder_pub)
            if self.is_initiator:
                self.ratchet = DoubleRatchet.for_initiator(root_key, responder_chain, responder_pub)
            else:
                # The responder's ephemeral key becomes its first ratchet key; the
                # ratchet deletes it at its first DH ratchet step.
                self.ratchet = DoubleRatchet.for_responder(root_key, responder_chain,
                                                           self._private_key, self.my_public)
            self.suite = SUITE_HYBRID if pq_used else SUITE_CLASSIC

        # Forward secrecy: the session no longer holds the ephemeral private key.
        self._private_key = None

    # ==================================================================
    # Messages
    # ==================================================================
    def needs_rekey(self) -> bool:
        too_many = self.send_seq >= self.MAX_MESSAGES
        too_old = time.monotonic() - self.created_at >= self.MAX_AGE_SECONDS
        return too_many or too_old

    def encrypt_message(self, data, msg_type: int = CHAT) -> bytes:
        """Encrypt text (str) or bytes and return the packet."""
        if not self.ready:
            raise SessionError("Handshake not finished yet")
        plaintext = data.encode("utf-8") if isinstance(data, str) else data

        if self.insecure:
            packet = build_packet(msg_type, self.send_seq, self.send_key, plaintext, insecure=True)
        else:
            packet = build_ratchet_packet(msg_type, self.ratchet, plaintext)
        self.send_seq += 1
        return packet

    def decrypt_packet(self, packet: bytes):
        """
        Returns (msg_type, plaintext_bytes).
        Raises InvalidTag if tampered, SessionError if replayed/out of order.
        """
        if not self.ready:
            raise SessionError("Handshake not finished yet")

        if self.insecure:
            # DEMO ONLY: AES-CTR, no tag, no replay check.
            msg_type, _seq, plaintext = open_packet(self.recv_key, packet, insecure=True)
            return msg_type, plaintext

        try:
            return open_ratchet_packet(self.ratchet, packet)
        except RatchetError as error:
            raise SessionError(str(error))
        except (InvalidTag, PacketError, SessionError):
            raise
        except ValueError:
            # e.g. a tampered ratchet key that isn't a valid X25519 point
            raise InvalidTag()

    def decrypt_message(self, packet: bytes) -> str:
        """Decrypt a CHAT packet and return the text."""
        _msg_type, plaintext = self.decrypt_packet(packet)
        return plaintext.decode("utf-8", errors="replace" if self.insecure else "strict")

    def fingerprint(self) -> str:
        """Short fingerprint of both ephemeral keys (changes every session)."""
        first, second = sorted([self.my_public, self.peer_public or b""])
        return crypto_utils.fingerprint(first + second)
