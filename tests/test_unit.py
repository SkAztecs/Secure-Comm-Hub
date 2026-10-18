"""
Unit tests for framing, crypto, packets and sessions.
Run from the project root:   pytest -v
"""

import asyncio

import pytest
from cryptography.exceptions import InvalidTag

from client.session import Session, SessionError
from common import crypto_utils
from common.framing import MAX_FRAME_SIZE, FrameError, recv_frame, send_frame
from common.message_types import CHAT
from common.packet import PacketError, build_packet, open_packet, parse_packet


# ---------------------------------------------------------------- framing
def run(coroutine):
    return asyncio.run(coroutine)


class FakeWriter:
    """Collects bytes instead of sending them over a network."""
    def __init__(self):
        self.buffer = b""

    def write(self, data):
        self.buffer += data

    async def drain(self):
        pass


def test_two_frames_stay_separate():
    async def scenario():
        writer = FakeWriter()
        await send_frame(writer, b"hello")
        await send_frame(writer, b"world")
        # Both frames arrive glued together, like real TCP might deliver them.
        reader = asyncio.StreamReader()
        reader.feed_data(writer.buffer)
        reader.feed_eof()
        return await recv_frame(reader), await recv_frame(reader)

    assert run(scenario()) == (b"hello", b"world")


def test_oversized_frame_rejected():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data((MAX_FRAME_SIZE + 1).to_bytes(4, "big"))
        reader.feed_eof()
        await recv_frame(reader)

    with pytest.raises(FrameError):
        run(scenario())


# ---------------------------------------------------------------- crypto
def make_keys():
    priv_a, pub_a = crypto_utils.generate_x25519_keypair()
    priv_b, pub_b = crypto_utils.generate_x25519_keypair()
    shared_a = crypto_utils.compute_shared_secret(priv_a, pub_b)
    shared_b = crypto_utils.compute_shared_secret(priv_b, pub_a)
    return shared_a, shared_b, pub_a, pub_b


def test_both_sides_derive_same_keys():
    shared_a, shared_b, pub_a, pub_b = make_keys()
    assert shared_a == shared_b
    assert crypto_utils.derive_session_keys(shared_a, pub_a, pub_b) == \
        crypto_utils.derive_session_keys(shared_b, pub_a, pub_b)


def test_two_direction_keys_are_different():
    shared, _, pub_a, pub_b = make_keys()
    key_i2r, key_r2i = crypto_utils.derive_session_keys(shared, pub_a, pub_b)
    assert key_i2r != key_r2i and len(key_i2r) == 32


def test_encrypt_decrypt_round_trip():
    key = b"k" * 32
    ct = crypto_utils.encrypt(key, 5, b"header", b"secret")
    assert crypto_utils.decrypt(key, 5, b"header", ct) == b"secret"


def test_flipped_bit_is_detected():
    key = b"k" * 32
    ct = bytearray(crypto_utils.encrypt(key, 0, b"h", b"secret"))
    ct[0] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto_utils.decrypt(key, 0, b"h", bytes(ct))


def test_wrong_header_is_detected():
    key = b"k" * 32
    ct = crypto_utils.encrypt(key, 0, b"header-1", b"secret")
    with pytest.raises(InvalidTag):
        crypto_utils.decrypt(key, 0, b"header-2", ct)


# ---------------------------------------------------------------- packets
def test_packet_round_trip():
    key = b"p" * 32
    packet = build_packet(CHAT, 7, key, b"hi bob")
    assert parse_packet(packet)["seq"] == 7
    assert open_packet(key, packet) == (CHAT, 7, b"hi bob")


def test_tampered_header_seq_is_detected():
    key = b"p" * 32
    packet = bytearray(build_packet(CHAT, 1, key, b"hi"))
    packet[9] ^= 0x01  # last byte of seq
    with pytest.raises((InvalidTag, PacketError)):
        open_packet(key, bytes(packet))


def test_truncated_packet_rejected():
    with pytest.raises(PacketError):
        parse_packet(b"\x01\x10short")


# ---------------------------------------------------------------- sessions
def make_session_pair(pq=True):
    alice = Session("bob", is_initiator=True, pq=pq)
    bob = Session("alice", is_initiator=False, pq=pq)
    alice.finish(bob.respond(alice.init_fields()))
    return alice, bob


def test_session_chat_both_directions():
    alice, bob = make_session_pair()
    assert bob.decrypt_message(alice.encrypt_message("hi bob")) == "hi bob"
    assert alice.decrypt_message(bob.encrypt_message("hi alice")) == "hi alice"


def test_private_key_deleted_after_handshake():
    alice, bob = make_session_pair()
    assert alice._private_key is None and bob._private_key is None


def test_replay_is_rejected():
    alice, bob = make_session_pair()
    packet = alice.encrypt_message("pay 100")
    bob.decrypt_message(packet)
    with pytest.raises(SessionError):
        bob.decrypt_message(packet)  # same packet again


def test_seq_increments():
    alice, bob = make_session_pair()
    for i in range(3):
        bob.decrypt_message(alice.encrypt_message(f"m{i}"))
    assert alice.send_seq == 3 and bob.ratchet.recv_n == 3


def test_send_before_handshake_fails():
    with pytest.raises(SessionError):
        Session("bob", is_initiator=True).encrypt_message("too early")
