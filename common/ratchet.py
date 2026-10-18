"""
ratchet.py - the Double Ratchet (simplified from the Signal specification)
==========================================================================

Problem with ONE key per session (Phase 1/2):
    if an attacker steals the session key, they can read EVERY message of that session.

Double Ratchet idea: a NEW key for EVERY message, and old keys are deleted.
    - steal one message key  -> you read ONE message
    - steal today's state     -> you can't read yesterday's messages   (forward secrecy)
    - and once the other side replies, you can't read tomorrow's either (break-in recovery)

Two ratchets work together:

  1. SYMMETRIC ratchet (every message) - a one-way "chain":
         chain_key_0 --HMAC--> chain_key_1 --HMAC--> chain_key_2 ...
              |                     |
           msg_key_0             msg_key_1  ...
     HMAC is one-way, so from chain_key_2 you can't go back to msg_key_0.

  2. DIFFIE-HELLMAN ratchet (every time the conversation changes direction):
     each message header carries the sender's current X25519 "ratchet" public key.
     When a NEW ratchet key arrives, both sides mix a fresh DH result into the
     ROOT key and start brand-new chains. Old chains (and their keys) are gone.

         root_key --(+ DH result)--> new root_key + new chain_key

Header of every message (sent in the clear, but authenticated as AES-GCM AAD):
    dh  = sender's current ratchet public key (32 bytes)
    pn  = how many messages the sender sent in its PREVIOUS chain
    n   = this message's number in the CURRENT chain

Reference: "The Double Ratchet Algorithm", Trevor Perrin & Moxie Marlinspike, Signal.
Simplifications for this project: no header encryption, AES-256-GCM per message.
"""

import hmac
import hashlib
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import crypto_utils

MAX_SKIP = 50            # max message keys we keep for messages that arrive late
MAX_STORED_SKIPPED = 200  # max skipped keys in total (memory / DoS limit)

HEADER_FORMAT = ">32sII"  # dh (32 bytes), pn (4 bytes), n (4 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # = 40


class RatchetError(Exception):
    """Replay, too many skipped messages, or a message that can't be decrypted."""


# ---------------------------------------------------------------------------
# The three key-derivation functions (KDFs)
# ---------------------------------------------------------------------------
def kdf_root(root_key: bytes, dh_output: bytes):
    """Root ratchet step: (root_key, DH result) -> (new root_key, new chain_key)."""
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=root_key,
               info=b"p1-ratchet-root").derive(dh_output)
    return okm[:32], okm[32:]


def kdf_chain(chain_key: bytes):
    """Symmetric ratchet step: chain_key -> (next chain_key, message_key)."""
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return next_chain_key, message_key


def message_cipher(message_key: bytes):
    """Expand one message key into an AES-256 key + a 12-byte nonce (each used once)."""
    okm = HKDF(algorithm=hashes.SHA256(), length=44, salt=b"\x00" * 32,
               info=b"p1-message-key").derive(message_key)
    return okm[:32], okm[32:]


def dh(private_key, public_bytes: bytes) -> bytes:
    return crypto_utils.compute_shared_secret(private_key, public_bytes)


# ---------------------------------------------------------------------------
# The ratchet state for ONE conversation
# ---------------------------------------------------------------------------
class DoubleRatchet:
    def __init__(self):
        self.dh_self_private = None   # my current ratchet private key
        self.dh_self_public = None    # ... and its public bytes
        self.dh_remote = None         # peer's current ratchet public key
        self.root_key = None
        self.send_chain = None        # chain key for messages I send
        self.recv_chain = None        # chain key for messages I receive
        self.send_n = 0               # messages sent in the current sending chain
        self.recv_n = 0               # messages received in the current receiving chain
        self.prev_send_n = 0          # messages sent in my previous sending chain
        self.skipped = {}             # (dh_pub, n) -> message key, for late messages
        self.used_message_keys = 0    # counter for the demo / benchmarks

    # ---------------- setup (right after the handshake) ----------------
    @classmethod
    def for_initiator(cls, root_key, responder_chain, responder_ratchet_pub):
        """
        The initiator (alice) starts with a FRESH ratchet key, so her very first
        message already triggers a DH ratchet step on bob's side.
        """
        state = cls()
        state.dh_self_private, state.dh_self_public = crypto_utils.generate_x25519_keypair()
        state.dh_remote = responder_ratchet_pub
        state.root_key, state.send_chain = kdf_root(
            root_key, dh(state.dh_self_private, responder_ratchet_pub))
        # bob may talk first using the extra chain from the handshake:
        state.recv_chain = responder_chain
        return state

    @classmethod
    def for_responder(cls, root_key, responder_chain, my_private, my_public):
        """
        The responder (bob) uses his handshake ephemeral key as his first ratchet key.
        It is kept ONLY until the first DH ratchet step, then deleted.
        """
        state = cls()
        state.dh_self_private, state.dh_self_public = my_private, my_public
        state.root_key = root_key
        state.send_chain = responder_chain
        return state

    # ---------------- sending ----------------
    def encrypt(self, plaintext: bytes, header_prefix: bytes):
        """
        Returns (header_bytes, ciphertext_with_tag).
        header_prefix (protocol version + type) is authenticated too.
        """
        self.send_chain, message_key = kdf_chain(self.send_chain)
        header = struct.pack(HEADER_FORMAT, self.dh_self_public, self.prev_send_n, self.send_n)
        self.send_n += 1

        key, nonce = message_cipher(message_key)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, header_prefix + header)
        self.used_message_keys += 1
        return header, ciphertext   # message_key goes out of scope = forgotten

    # ---------------- receiving ----------------
    def decrypt(self, header: bytes, ciphertext: bytes, header_prefix: bytes) -> bytes:
        """
        Decrypt one message. ALL-OR-NOTHING: if anything fails (tampering, garbage
        header), the state is restored exactly as it was, so an attacker can't
        knock the conversation out of sync with one bad packet.
        """
        snapshot = dict(self.__dict__)
        snapshot["skipped"] = dict(self.skipped)
        try:
            return self._decrypt(header, ciphertext, header_prefix)
        except Exception:
            self.__dict__.update(snapshot)
            raise

    def _decrypt(self, header, ciphertext, header_prefix):
        if len(header) != HEADER_SIZE:
            raise RatchetError("Bad ratchet header size")
        their_dh, prev_n, n = struct.unpack(HEADER_FORMAT, header)
        aad = header_prefix + header

        # 1) A late message whose key we saved earlier?
        saved = self.skipped.pop((their_dh, n), None)
        if saved is not None:
            return self._open(saved, ciphertext, aad)

        # 2) A NEW ratchet key from the peer -> DH ratchet step.
        if their_dh != self.dh_remote:
            self._skip_until(prev_n)        # save keys of messages still on their way
            self._dh_ratchet_step(their_dh)
        elif n < self.recv_n:
            # Same chain, but this number was already used and isn't a saved late one.
            raise RatchetError(f"REPLAY_OR_REORDER: message {n} of this chain was already received")

        # 3) Walk the receiving chain forward to message n.
        self._skip_until(n)
        self.recv_chain, message_key = kdf_chain(self.recv_chain)
        self.recv_n += 1
        return self._open(message_key, ciphertext, aad)

    def _open(self, message_key, ciphertext, aad):
        key, nonce = message_cipher(message_key)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)  # InvalidTag if tampered
        self.used_message_keys += 1
        return plaintext

    def _skip_until(self, until_n):
        """Store message keys for messages that haven't arrived yet (out of order)."""
        if self.recv_chain is None:
            return
        if until_n - self.recv_n > MAX_SKIP:
            raise RatchetError(f"Too many skipped messages ({until_n - self.recv_n})")
        while self.recv_n < until_n:
            self.recv_chain, message_key = kdf_chain(self.recv_chain)
            self.skipped[(self.dh_remote, self.recv_n)] = message_key
            self.recv_n += 1
        # Drop the oldest saved keys if there are too many.
        while len(self.skipped) > MAX_STORED_SKIPPED:
            self.skipped.pop(next(iter(self.skipped)))

    def _dh_ratchet_step(self, their_dh):
        """The conversation changed direction: new DH -> new chains, old keys gone."""
        self.prev_send_n = self.send_n
        self.send_n = 0
        self.recv_n = 0
        self.dh_remote = their_dh

        # New RECEIVING chain from (my current key x their new key).
        self.root_key, self.recv_chain = kdf_root(self.root_key, dh(self.dh_self_private, their_dh))

        # Brand-new ratchet key pair for me; the old private key is dropped here.
        self.dh_self_private, self.dh_self_public = crypto_utils.generate_x25519_keypair()
        self.root_key, self.send_chain = kdf_root(self.root_key, dh(self.dh_self_private, their_dh))
