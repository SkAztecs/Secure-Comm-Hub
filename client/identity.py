"""
identity.py
-----------
Two things live here:

1. Identity  - this user's LONG-TERM Ed25519 key pair.
   The private key is stored ENCRYPTED on disk:
        passphrase --scrypt--> 32-byte key --AES-256-GCM--> encrypted private key
   So someone who copies the keys/ folder still can't use it without the passphrase.

2. KnownPeers - "trust on first use" (TOFU), like SSH's known_hosts.
   The first time we see bob's identity key we save it.
   If it is ever DIFFERENT later, someone may be impersonating bob -> we refuse.

Files (per user):
    keys/<username>/identity.json      encrypted identity key
    keys/<username>/known_peers.json   peer name -> identity public key (hex)
"""

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import crypto_utils


class IdentityError(Exception):
    """Wrong passphrase, corrupted key file, etc."""


class Identity:
    def __init__(self, username, private_key, public_bytes):
        self.username = username
        self._private_key = private_key
        self.public_bytes = public_bytes

    def sign(self, data: bytes) -> bytes:
        return crypto_utils.sign(self._private_key, data)

    # ------------------------------------------------------------------
    # Load or create
    # ------------------------------------------------------------------
    @staticmethod
    def exists(username: str, keys_dir: str = "keys") -> bool:
        """True if this user already has an identity key on this machine."""
        return os.path.exists(os.path.join(keys_dir, username, "identity.json"))

    @classmethod
    def load_or_create(cls, username: str, passphrase: str, keys_dir: str = "keys"):
        """
        Load keys/<username>/identity.json, or create it on first run.
        Raises IdentityError if the passphrase is wrong.
        """
        folder = os.path.join(keys_dir, username)
        path = os.path.join(folder, "identity.json")

        if os.path.exists(path):
            return cls._load(username, passphrase, path)

        os.makedirs(folder, exist_ok=True)
        private_key, public_bytes = crypto_utils.generate_identity_keypair()
        cls._save(username, passphrase, path, private_key, public_bytes)
        return cls(username, private_key, public_bytes)

    @staticmethod
    def _save(username, passphrase, path, private_key, public_bytes):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = crypto_utils.key_from_passphrase(passphrase, salt)
        raw_private = crypto_utils.identity_private_to_bytes(private_key)

        # AAD = username: the file can't be renamed to another user and still decrypt.
        ciphertext = AESGCM(key).encrypt(nonce, raw_private, username.encode())

        data = {
            "version": 1,
            "username": username,
            "kdf": "scrypt n=2^15 r=8 p=1",
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "encrypted_private_key": ciphertext.hex(),
            "public_key": public_bytes.hex(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def _load(cls, username, passphrase, path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        key = crypto_utils.key_from_passphrase(passphrase, bytes.fromhex(data["salt"]))
        try:
            raw_private = AESGCM(key).decrypt(
                bytes.fromhex(data["nonce"]),
                bytes.fromhex(data["encrypted_private_key"]),
                username.encode())
        except InvalidTag:
            raise IdentityError("Wrong key passphrase (or the key file was modified)")

        private_key = crypto_utils.identity_private_from_bytes(raw_private)
        return cls(username, private_key, bytes.fromhex(data["public_key"]))


class KnownPeers:
    """Trust-on-first-use store: peer name -> identity public key."""

    def __init__(self, username: str, keys_dir: str = "keys"):
        folder = os.path.join(keys_dir, username)
        os.makedirs(folder, exist_ok=True)
        self.path = os.path.join(folder, "known_peers.json")
        self.peers = {}
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                self.peers = json.load(f)

    def check(self, peer: str, identity_public: bytes) -> str:
        """
        Returns:
            "new"      first time we see this peer (key saved now)
            "match"    same key as before
            "changed"  DIFFERENT key -> do not trust automatically
        """
        saved = self.peers.get(peer)
        if saved is None:
            self.trust(peer, identity_public)
            return "new"
        if saved == identity_public.hex():
            return "match"
        return "changed"

    def trust(self, peer: str, identity_public: bytes) -> None:
        """Save (or replace) the trusted key for `peer`."""
        self.peers[peer] = identity_public.hex()
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.peers, f, indent=2)
