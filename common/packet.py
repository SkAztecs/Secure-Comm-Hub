"""
packet.py
---------
Builds and reads the ENCRYPTED packet (the part only the two clients can open).

Layout (see "Encrypted packet format" in the protocol spec):

    +-----+------+---------+-------------+----------------------+---------+
    | ver | type |   seq   |    nonce    |      ciphertext      |   tag   |
    | 1 B | 1 B  |   8 B   |    12 B     |      variable        |  16 B   |
    +-----+------+---------+-------------+----------------------+---------+
    |------ header ------|
      (used as AAD: protected but not encrypted)
"""

import struct

from common import crypto_utils
from common.message_types import PROTOCOL_VERSION

# ">BBQ" = big-endian: unsigned char (ver), unsigned char (type), unsigned long long (seq)
HEADER_FORMAT = ">BBQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # = 10 bytes

MIN_PACKET_SIZE = HEADER_SIZE + crypto_utils.NONCE_SIZE + crypto_utils.TAG_SIZE


class PacketError(Exception):
    """Raised when a packet is malformed (too short, wrong version, bad nonce)."""


def build_header(msg_type: int, seq: int) -> bytes:
    """Pack the 10-byte header: version, type, sequence number."""
    return struct.pack(HEADER_FORMAT, PROTOCOL_VERSION, msg_type, seq)


def build_packet(msg_type: int, seq: int, key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt `plaintext` and return the full packet bytes.
        header + nonce + (ciphertext + tag)
    """
    header = build_header(msg_type, seq)
    nonce = crypto_utils.nonce_from_seq(seq)
    ciphertext_and_tag = crypto_utils.encrypt(key, seq, header, plaintext)
    return header + nonce + ciphertext_and_tag


def parse_packet(packet: bytes):
    """
    Split a packet into its parts WITHOUT decrypting.
    Returns a dict: version, type, seq, nonce, header, ciphertext (incl. tag).
    """
    if len(packet) < MIN_PACKET_SIZE:
        raise PacketError(f"Packet too short: {len(packet)} bytes")

    header = packet[:HEADER_SIZE]
    version, msg_type, seq = struct.unpack(HEADER_FORMAT, header)

    if version != PROTOCOL_VERSION:
        raise PacketError(f"Unknown protocol version: {version}")

    nonce_start = HEADER_SIZE
    nonce_end = HEADER_SIZE + crypto_utils.NONCE_SIZE
    nonce = packet[nonce_start:nonce_end]
    ciphertext = packet[nonce_end:]

    # The nonce must match what seq says it should be.
    # (Stops an attacker from pairing a header with a different nonce.)
    if nonce != crypto_utils.nonce_from_seq(seq):
        raise PacketError("Nonce does not match sequence number")

    return {
        "version": version,
        "type": msg_type,
        "seq": seq,
        "nonce": nonce,
        "header": header,
        "ciphertext": ciphertext,
    }


def open_packet(key: bytes, packet: bytes):
    """
    Parse + decrypt. Returns (msg_type, seq, plaintext).
    Raises PacketError (bad format) or cryptography.exceptions.InvalidTag (tampered).
    """
    parts = parse_packet(packet)
    plaintext = crypto_utils.decrypt(key, parts["seq"], parts["header"], parts["ciphertext"])
    return parts["type"], parts["seq"], plaintext
