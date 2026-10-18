"""
Phase 3 tests: post-quantum hybrid handshake + Double Ratchet.
"""

import asyncio

import pytest
from cryptography.exceptions import InvalidTag

from client.session import SUITE_CLASSIC, SUITE_HYBRID, Session, SessionError
from common import crypto_utils
from common.handshake import init_transcript
from common.ratchet import MAX_SKIP, kdf_chain
from tests.helpers import connect, make_client, start_relay


def pair(pq=True, responder_pq=None):
    alice = Session("bob", is_initiator=True, pq=pq)
    bob = Session("alice", is_initiator=False, pq=pq if responder_pq is None else responder_pq)
    alice.finish(bob.respond(alice.init_fields()))
    return alice, bob


# ================================================================ post-quantum
def test_hybrid_handshake_uses_mlkem():
    alice, bob = pair(pq=True)
    assert alice.suite == bob.suite == SUITE_HYBRID
    assert bob.decrypt_message(alice.encrypt_message("pq hello")) == "pq hello"


def test_classic_handshake_still_works():
    alice, bob = pair(pq=False)
    assert alice.suite == bob.suite == SUITE_CLASSIC
    assert bob.decrypt_message(alice.encrypt_message("classic")) == "classic"


def test_kem_fields_have_the_right_sizes():
    alice = Session("bob", is_initiator=True)
    fields = alice.init_fields()
    reply = Session("alice", is_initiator=False).respond(fields)
    assert len(fields["kem_pub"]) == 1184 and len(reply["kem_ct"]) == 1088


def test_pq_secret_really_changes_the_keys():
    """Same X25519 keys, different ML-KEM result -> different root key."""
    x = b"x" * 32
    root_a, _ = crypto_utils.derive_root_material(x, b"pq-secret-1".ljust(32, b"0"), b"a" * 32, b"b" * 32)
    root_b, _ = crypto_utils.derive_root_material(x, b"pq-secret-2".ljust(32, b"0"), b"a" * 32, b"b" * 32)
    assert root_a != root_b


def test_initiator_refuses_reply_without_kem_ciphertext():
    """If we offered post-quantum, a reply that drops it is a downgrade -> refuse."""
    alice = Session("bob", is_initiator=True, pq=True)
    fields = alice.init_fields()
    reply = Session("alice", is_initiator=False).respond(fields)
    del reply["kem_ct"]
    with pytest.raises(SessionError):
        alice.finish(reply)


def test_stripping_kem_pub_breaks_the_signature():
    """An attacker removing kem_pub (to force classic mode) invalidates alice's signature."""
    identity, identity_pub = crypto_utils.generate_identity_keypair()
    fields = Session("bob", is_initiator=True).init_fields()
    signature = crypto_utils.sign(identity, init_transcript("alice", "bob", fields))
    stripped = {"pub": fields["pub"]}
    assert crypto_utils.verify_signature(identity_pub, signature, init_transcript("alice", "bob", fields))
    assert not crypto_utils.verify_signature(identity_pub, signature, init_transcript("alice", "bob", stripped))


def test_classic_initiator_with_pq_capable_responder():
    """Interop: --no-pq on one side gives a classic session, not an error."""
    alice, bob = pair(pq=False, responder_pq=True)
    assert alice.suite == bob.suite == SUITE_CLASSIC


# ================================================================ Double Ratchet
def test_every_message_gets_a_new_key():
    alice, bob = pair()
    seen_chain_keys = set()
    for i in range(5):
        seen_chain_keys.add(alice.ratchet.send_chain)
        bob.decrypt_message(alice.encrypt_message(f"m{i}"))
    assert len(seen_chain_keys) == 5


def test_ping_pong_triggers_dh_ratchet_steps():
    alice, bob = pair()
    ratchet_keys = set()
    for i in range(4):
        assert bob.decrypt_message(alice.encrypt_message(f"a{i}")) == f"a{i}"
        ratchet_keys.add(alice.ratchet.dh_self_public)
        assert alice.decrypt_message(bob.encrypt_message(f"b{i}")) == f"b{i}"
        ratchet_keys.add(bob.ratchet.dh_self_public)
    # Every change of direction produced a fresh ratchet key.
    assert len(ratchet_keys) == 8


def test_responder_can_talk_first():
    alice, bob = pair()
    assert alice.decrypt_message(bob.encrypt_message("bob first")) == "bob first"
    assert bob.decrypt_message(alice.encrypt_message("then alice")) == "then alice"


def test_out_of_order_messages_are_decrypted():
    alice, bob = pair()
    packets = [alice.encrypt_message(f"m{i}") for i in range(4)]
    assert bob.decrypt_message(packets[2]) == "m2"   # skips m0, m1 (keys saved)
    assert bob.decrypt_message(packets[0]) == "m0"
    assert bob.decrypt_message(packets[3]) == "m3"
    assert bob.decrypt_message(packets[1]) == "m1"


def test_late_message_from_previous_chain():
    """A message delayed across a DH ratchet step still decrypts (its key was saved)."""
    alice, bob = pair()
    bob.decrypt_message(alice.encrypt_message("first"))
    delayed = alice.encrypt_message("delayed in the network")   # chain 1, message 1
    alice.decrypt_message(bob.encrypt_message("reply"))         # alice moves to chain 2
    bob.decrypt_message(alice.encrypt_message("new chain"))     # bob ratchets, saves msg 1's key
    assert bob.decrypt_message(delayed) == "delayed in the network"


def test_replay_is_rejected_by_the_ratchet():
    alice, bob = pair()
    packet = alice.encrypt_message("pay 100")
    bob.decrypt_message(packet)
    with pytest.raises(SessionError):
        bob.decrypt_message(packet)


def test_too_many_skipped_messages_is_refused():
    alice, bob = pair()
    for _ in range(MAX_SKIP + 1):
        alice.encrypt_message("lost")
    with pytest.raises(SessionError):
        bob.decrypt_message(alice.encrypt_message("far ahead"))


def test_tampered_packet_leaves_state_untouched():
    """A forged packet must not desynchronise the ratchet (all-or-nothing decrypt)."""
    alice, bob = pair()
    good = alice.encrypt_message("hello")
    before = dict(bob.ratchet.__dict__)

    bad = bytearray(good)
    bad[10] ^= 0xFF               # inside the ratchet public key -> fake DH ratchet step
    with pytest.raises(InvalidTag):
        bob.decrypt_message(bytes(bad))
    assert bob.ratchet.__dict__ == before

    assert bob.decrypt_message(good) == "hello"   # the real message still works


def test_forward_secrecy_old_keys_cannot_be_recomputed():
    """
    An attacker steals bob's state AFTER messages 0 and 1. From the stolen chain
    key they can only walk FORWARD (HMAC is one-way), so message 0's key - and
    therefore message 0 - is out of reach.
    """
    alice, bob = pair()
    chain_before_msg0 = alice.ratchet.send_chain
    _, message_key_0 = kdf_chain(chain_before_msg0)       # the real key of message 0

    bob.decrypt_message(alice.encrypt_message("secret 0"))
    bob.decrypt_message(alice.encrypt_message("secret 1"))
    stolen_chain = bob.ratchet.recv_chain

    reachable_keys, chain = set(), stolen_chain
    for _ in range(1000):
        chain, message_key = kdf_chain(chain)
        reachable_keys.add(message_key)

    assert message_key_0 not in reachable_keys
    assert bob.ratchet.skipped == {}   # and no old message keys are kept around


# ================================================================ end to end
def test_chat_through_relay_uses_hybrid_and_ratchet(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        inbox = asyncio.Queue()
        alice = make_client(str(tmp_path), "alice")
        bob = make_client(str(tmp_path), "bob", inbox)
        await connect(alice, relay)
        await connect(bob, relay)
        await alice.start_chat("bob")
        for i in range(3):
            await alice.send_chat("bob", f"hi {i}")
            await bob.send_chat("alice", f"yo {i}")
        received = [(await asyncio.wait_for(inbox.get(), 5))[1] for _ in range(3)]
        suite = alice.sessions["bob"].suite
        trust = alice.describe_trust("bob")
        await alice.close()
        await bob.close()
        await relay.stop()
        return received, suite, trust

    received, suite, trust = asyncio.run(scenario())
    assert received == ["hi 0", "hi 1", "hi 2"]
    assert suite == SUITE_HYBRID
    assert "ML-KEM-768" in trust and "Double Ratchet" in trust


def test_insecure_and_secure_clients_refuse_each_other(tmp_path, monkeypatch):
    import client.client_core as core
    monkeypatch.setattr(core, "HANDSHAKE_TIMEOUT", 1)

    async def scenario():
        relay = await start_relay(str(tmp_path))
        infos = []
        alice = make_client(str(tmp_path), "alice", insecure=True)
        bob = make_client(str(tmp_path), "bob", infos=infos)
        await connect(alice, relay)
        await connect(bob, relay)
        try:
            await alice.start_chat("bob")
            ok = True
        except ConnectionError:
            ok = False
        await alice.close()
        await bob.close()
        await relay.stop()
        return ok, infos

    ok, infos = asyncio.run(scenario())
    assert not ok
    assert any("Both must match" in i for i in infos)
