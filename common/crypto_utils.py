"""
crypto_utils.py
---------------
Small, readable wrappers around the `cryptography` library.

RULE: we never write our own crypto. Every primitive here
(X25519, HKDF, AES-GCM) comes from the audited `cryptography` library.

What lives here:
    1. X25519 key pairs          -> for the Diffie-Hellman key exchange
    2. derive_session_keys()     -> HKDF turns the shared secret into 2 AES keys
    3. encrypt() / decrypt()     -> AES-256-GCM with a nonce built from `seq`
"""

import hashlib
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# "info" string for HKDF. Changing the protocol version should change this,
# so keys from v1 can never be confused with keys from v2.
HKDF_INFO = b"p1-chat-v1"

KEY_SIZE = 32    # 32 bytes = 256-bit AES key
NONCE_SIZE = 12  # AES-GCM standard nonce size
TAG_SIZE = 16    # AES-GCM authentication tag size


# ---------------------------------------------------------------------------
# 1. X25519 key pairs
# ---------------------------------------------------------------------------

def generate_x25519_keypair():
    """
    Make a brand-new (ephemeral) X25519 key pair.
    Returns (private_key_object, public_key_bytes).
    The public key is 32 bytes and is safe to send over the network.
    """
    private_key = X25519PrivateKey.generate()
    public_bytes = public_key_to_bytes(private_key.public_key())
    return private_key, public_bytes


def public_key_to_bytes(public_key: X25519PublicKey) -> bytes:
    """Turn a public key object into its raw 32 bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def compute_shared_secret(my_private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """
    Diffie-Hellman: my private key + their public key = shared secret.
    Both sides get the SAME 32 bytes without ever sending them.
    """
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return my_private_key.exchange(peer_public_key)


# ---------------------------------------------------------------------------
# 2. Key derivation (HKDF-SHA256)
# ---------------------------------------------------------------------------

def derive_session_keys(shared_secret: bytes, initiator_pub: bytes, responder_pub: bytes):
    """
    Turn the raw shared secret into TWO separate AES-256 keys:
        key_i2r : initiator -> responder
        key_r2i : responder -> initiator

    Why two keys? So each direction has its own key, and the same
    (key, nonce) pair can never be used by both sides at once.

    salt = SHA256(sorted public keys)  -> both sides compute the same salt
    okm  = HKDF(shared, salt, info, 64 bytes)
    key_i2r = okm[0:32], key_r2i = okm[32:64]
    """
    # Sort so that both sides build the salt in the same order.
    first, second = sorted([initiator_pub, responder_pub])
    salt = hashlib.sha256(first + second).digest()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * KEY_SIZE,  # 64 bytes -> two 32-byte keys
        salt=salt,
        info=HKDF_INFO,
    )
    okm = hkdf.derive(shared_secret)  # "output keying material"

    key_i2r = okm[:KEY_SIZE]
    key_r2i = okm[KEY_SIZE:]
    return key_i2r, key_r2i


# ---------------------------------------------------------------------------
# 3. AES-256-GCM encrypt / decrypt
# ---------------------------------------------------------------------------

def nonce_from_seq(seq: int) -> bytes:
    """
    Build the 12-byte nonce from the message sequence number:
        4 zero bytes + 8-byte seq (big-endian)
    Because seq only goes UP and each direction has its own key,
    the same nonce is NEVER reused with the same key (the #1 GCM rule).
    """
    return b"\x00\x00\x00\x00" + struct.pack(">Q", seq)


def encrypt(key: bytes, seq: int, header: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt `plaintext` with AES-256-GCM.
    `header` is passed as AAD (associated data): it is NOT encrypted,
    but it IS protected - changing even one header bit breaks decryption.
    Returns ciphertext + 16-byte tag (glued together by the library).
    """
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce_from_seq(seq), plaintext, header)


def decrypt(key: bytes, seq: int, header: bytes, ciphertext_and_tag: bytes) -> bytes:
    """
    Decrypt and verify. If ANYTHING was changed (ciphertext, tag or header),
    this raises cryptography.exceptions.InvalidTag.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce_from_seq(seq), ciphertext_and_tag, header)


def fingerprint(public_bytes: bytes) -> str:
    """Short, human-readable fingerprint of a public key (for display/logs)."""
    return hashlib.sha256(public_bytes).hexdigest()[:16]
