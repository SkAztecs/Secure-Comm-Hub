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


# ===========================================================================
# PHASE 2 ADDITIONS
# ===========================================================================

# ---------------------------------------------------------------------------
# 4. Ed25519 identity keys (long-term, one per user)
# ---------------------------------------------------------------------------
# The X25519 keys above are EPHEMERAL (new every session) -> forward secrecy.
# But ephemeral keys alone don't prove WHO you are talking to: a man-in-the-middle
# can swap them. So each user also has a LONG-TERM Ed25519 identity key and
# SIGNS their ephemeral key with it. Swapping the ephemeral key breaks the signature.

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_identity_keypair():
    """New long-term Ed25519 identity. Returns (private_key_object, public_bytes)."""
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return private_key, public_bytes


def identity_private_to_bytes(private_key: Ed25519PrivateKey) -> bytes:
    """Raw 32-byte private key (only ever stored ENCRYPTED, see client/identity.py)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())


def identity_private_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Ed25519 signature (64 bytes) over `data`."""
    return private_key.sign(data)


def verify_signature(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """True if `signature` over `data` was made by the owner of `public_bytes`."""
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def safety_number(identity_a: bytes, identity_b: bytes) -> str:
    """
    A short number BOTH users see. If it matches on both screens (compare in
    person or on a call), nobody is in the middle.
        SHA-256(sorted identity keys) -> 6 groups of 5 digits
    Example: "48213 09921 77310 26645 51208 93017"
    """
    first, second = sorted([identity_a, identity_b])
    digest = hashlib.sha256(first + second).digest()
    groups = []
    for i in range(6):
        chunk = digest[i * 5:(i + 1) * 5]            # 5 bytes per group
        groups.append(f"{int.from_bytes(chunk, 'big') % 100000:05d}")
    return " ".join(groups)


# ---------------------------------------------------------------------------
# 5. Password-based key (scrypt) - used to encrypt the identity key at rest
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """
    Turn a human passphrase into a 32-byte AES key.
    scrypt is deliberately SLOW and memory-hungry, so guessing passphrases is expensive.
    n=2**15, r=8, p=1 uses about 32 MB of RAM per guess.
    """
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=2 ** 15, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


# ---------------------------------------------------------------------------
# 6. INSECURE DEMO MODE ONLY: AES-256-CTR with NO authentication
# ---------------------------------------------------------------------------
# Used ONLY when a client runs with --insecure, to show in the demo what happens
# WITHOUT integrity protection: flipping one ciphertext bit flips the same
# plaintext bit ("pay 100" -> "pay 900") and nobody notices.
# The secure mode (AES-GCM) detects that. Never use this for real messages.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _ctr_cipher(key: bytes, seq: int):
    # 16-byte CTR starting block = 12-byte nonce from seq + 4-byte counter (0)
    iv = nonce_from_seq(seq) + b"\x00\x00\x00\x00"
    return Cipher(algorithms.AES(key), modes.CTR(iv))


def encrypt_ctr_insecure(key: bytes, seq: int, plaintext: bytes) -> bytes:
    encryptor = _ctr_cipher(key, seq).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_ctr_insecure(key: bytes, seq: int, ciphertext: bytes) -> bytes:
    decryptor = _ctr_cipher(key, seq).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ===========================================================================
# PHASE 3 ADDITIONS
# ===========================================================================

# ---------------------------------------------------------------------------
# 7. ML-KEM-768 (post-quantum key encapsulation, FIPS 203)
# ---------------------------------------------------------------------------
# A future large quantum computer could break X25519 (Shor's algorithm).
# An attacker can RECORD our traffic today and decrypt it later
# ("harvest now, decrypt later"). ML-KEM is designed to resist quantum attacks.
#
# We use a HYBRID: X25519 AND ML-KEM-768 together. The session key depends on
# BOTH secrets, so an attacker must break both. This is the same idea as
# Signal's PQXDH and Chrome's X25519MLKEM768.
#
# How a KEM works (different from Diffie-Hellman):
#   1. Alice makes a key pair and sends her PUBLIC key (1184 bytes).
#   2. Bob "encapsulates": gets (shared_secret, ciphertext) and sends the ciphertext (1088 bytes).
#   3. Alice "decapsulates" the ciphertext with her PRIVATE key -> same shared_secret (32 bytes).

try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import (
        MLKEM768PrivateKey,
        MLKEM768PublicKey,
    )
    HAS_MLKEM = True
except ImportError:          # cryptography older than 47.0
    HAS_MLKEM = False


def generate_mlkem_keypair():
    """Returns (private_key_object, public_bytes[1184])."""
    private_key = MLKEM768PrivateKey.generate()
    return private_key, private_key.public_key().public_bytes_raw()


def mlkem_encapsulate(public_bytes: bytes):
    """Returns (shared_secret[32], ciphertext[1088])."""
    return MLKEM768PublicKey.from_public_bytes(public_bytes).encapsulate()


def mlkem_decapsulate(private_key, ciphertext: bytes) -> bytes:
    """Returns the same 32-byte shared secret the encapsulating side got."""
    return private_key.decapsulate(ciphertext)


# ---------------------------------------------------------------------------
# 8. Root key for the Double Ratchet
# ---------------------------------------------------------------------------
HKDF_INFO_V2 = b"p1-chat-v2"


def derive_root_material(x25519_shared: bytes, pq_shared: bytes,
                         initiator_pub: bytes, responder_pub: bytes):
    """
    Combine the handshake secrets into the Double Ratchet's starting values.
        ikm  = x25519_shared || pq_shared      (pq_shared is b"" in classic mode)
        okm  = HKDF-SHA256(ikm, salt = SHA256(sorted ephemeral keys), info, 64 bytes)
        root_key           = okm[0:32]    -> starts the ratchet
        responder_chain    = okm[32:64]   -> lets the responder send before it has ratcheted
    """
    first, second = sorted([initiator_pub, responder_pub])
    salt = hashlib.sha256(first + second).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt,
               info=HKDF_INFO_V2).derive(x25519_shared + pq_shared)
    return okm[:32], okm[32:]
