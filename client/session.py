"""
session.py
----------
One Session = one encrypted conversation with ONE peer.

It holds:
    - my ephemeral X25519 private key (only until the handshake finishes)
    - the two AES keys (send_key, recv_key)
    - the two sequence counters (send_seq, recv_seq)
    - the peer's long-term identity key (Phase 2)
    - counters for rekeying and for tag failures (Phase 2)

Handshake (Phase 2 = signed, see common/handshake.py for what is signed):

    Alice (initiator)                           Bob (responder)
    -----------------                           ---------------
    make ephemeral key pair
    KEY_INIT {eph_A, id_A, sig_A}  ---------->  check id_A (TOFU), verify sig_A
                                                make ephemeral key pair
                      <----------  KEY_RESP {eph_B, id_B, sig_B}
    check id_B (TOFU), verify sig_B
    shared = X25519(priv_A, eph_B)              shared = X25519(priv_B, eph_A)
    keys   = HKDF(shared, ...)                  keys   = HKDF(shared, ...)
    delete priv_A                               delete priv_B   (forward secrecy)
"""

import time

from common import crypto_utils
from common.message_types import CHAT
from common.packet import build_packet, open_packet


class SessionError(Exception):
    """Raised for replays, out-of-order packets or using a session too early."""


class Session:
    # Rekey rules (Step 13): fresh handshake after this many messages OR this many seconds.
    MAX_MESSAGES = 1000
    MAX_AGE_SECONDS = 60 * 60

    # Close the session after this many tampered packets (Step 13).
    MAX_TAG_FAILURES = 3

    def __init__(self, peer: str, is_initiator: bool, insecure: bool = False):
        self.peer = peer
        self.is_initiator = is_initiator
        # insecure=True only for the attack demo: AES-CTR (no integrity) + no replay check.
        self.insecure = insecure

        # Fresh key pair for THIS session only.
        self._private_key, self.my_public = crypto_utils.generate_x25519_keypair()
        self.peer_public = None
        self.peer_identity = None  # peer's Ed25519 public key (set by the client)

        self.send_key = None
        self.recv_key = None
        self.send_seq = 0  # next seq number I will SEND
        self.recv_seq = 0  # next seq number I EXPECT to receive

        self.created_at = time.monotonic()
        self.tag_failures = 0

    @property
    def ready(self) -> bool:
        """True once both AES keys exist."""
        return self.send_key is not None

    def complete(self, peer_public: bytes) -> None:
        """
        Finish the handshake once we have the peer's ephemeral public key.
        Computes the shared secret, derives the keys, then DELETES
        our private key so it can never be stolen later.
        """
        if len(peer_public) != 32:
            raise SessionError("Peer public key must be 32 bytes")

        self.peer_public = peer_public
        shared = crypto_utils.compute_shared_secret(self._private_key, peer_public)

        # Both sides must pass (initiator_pub, responder_pub) in the same order.
        if self.is_initiator:
            initiator_pub, responder_pub = self.my_public, peer_public
        else:
            initiator_pub, responder_pub = peer_public, self.my_public

        key_i2r, key_r2i = crypto_utils.derive_session_keys(shared, initiator_pub, responder_pub)

        # Initiator SENDS with i->r and RECEIVES with r->i. Responder is the opposite.
        if self.is_initiator:
            self.send_key, self.recv_key = key_i2r, key_r2i
        else:
            self.send_key, self.recv_key = key_r2i, key_i2r

        # Forward secrecy: throw away the ephemeral private key.
        self._private_key = None

    def needs_rekey(self) -> bool:
        """True when this session has been used too much or for too long."""
        too_many = self.send_seq >= self.MAX_MESSAGES
        too_old = time.monotonic() - self.created_at >= self.MAX_AGE_SECONDS
        return too_many or too_old

    def encrypt_message(self, text: str, msg_type: int = CHAT) -> bytes:
        """Encrypt a text message and return the packet bytes."""
        if not self.ready:
            raise SessionError("Handshake not finished yet")

        packet = build_packet(msg_type, self.send_seq, self.send_key,
                              text.encode("utf-8"), insecure=self.insecure)
        self.send_seq += 1  # never reuse a seq -> never reuse a nonce
        return packet

    def decrypt_message(self, packet: bytes) -> str:
        """
        Decrypt a packet and return the text.
        Raises InvalidTag if tampered, SessionError if replayed/out of order.
        """
        if not self.ready:
            raise SessionError("Handshake not finished yet")

        msg_type, seq, plaintext = open_packet(self.recv_key, packet, insecure=self.insecure)

        if self.insecure:
            # DEMO ONLY: no replay check, so a resent packet is accepted again.
            return plaintext.decode("utf-8", errors="replace")

        # Replay protection: TCP keeps order, so the ONLY valid seq is the next one.
        # (Checked after decryption so an attacker can't fake a seq without the key.)
        if seq != self.recv_seq:
            raise SessionError(f"REPLAY_OR_REORDER: expected seq {self.recv_seq}, got {seq}")

        self.recv_seq += 1
        return plaintext.decode("utf-8")

    def fingerprint(self) -> str:
        """Short fingerprint of both ephemeral keys (changes every session)."""
        first, second = sorted([self.my_public, self.peer_public or b""])
        return crypto_utils.fingerprint(first + second)
