"""
Runs every attack proxy twice: against --insecure clients (attack must WORK)
and against secure clients (attack must FAIL and be logged).
This is the automated version of the Phase 2 demo table.
"""

import asyncio

import client.client_core as core
from attacks.mitm_proxy import MitmProxy
from attacks.replay_attack import ReplayProxy
from attacks.tamper_attack import TamperProxy
from tests.helpers import PASSWORD, make_client, nothing_arrives, read_events, start_relay


async def setup(tmp, proxy_class, insecure, **proxy_kwargs):
    """relay <- proxy <- alice, bob. Returns everything needed by a test."""
    relay = await start_relay(tmp)
    proxy = proxy_class(0, "127.0.0.1", relay.port, **proxy_kwargs)
    await proxy.start()

    inbox, infos = asyncio.Queue(), []
    alice = make_client(tmp, "alice", insecure=insecure)
    bob = make_client(tmp, "bob", inbox, infos, insecure=insecure)
    for c in (alice, bob):
        await c.connect("127.0.0.1", proxy.listen_port, PASSWORD, register=True)
    return relay, proxy, alice, bob, inbox, infos


async def teardown(relay, proxy, *clients):
    for c in clients:
        await c.close()
    await proxy.stop()
    await relay.stop()


# ---------------------------------------------------------------- MITM
def test_mitm_works_against_insecure_clients(tmp_path, capsys):
    async def scenario():
        relay, proxy, alice, bob, inbox, _ = await setup(str(tmp_path), MitmProxy, insecure=True)
        await alice.start_chat("bob")
        await alice.send_chat("bob", "the vault code is 4321")
        got = await asyncio.wait_for(inbox.get(), 5)
        await teardown(relay, proxy, alice, bob)
        return got

    assert asyncio.run(scenario()) == ("alice", "the vault code is 4321")
    output = capsys.readouterr().out
    assert "INTERCEPTED alice -> bob: 'the vault code is 4321'" in output


def test_mitm_is_detected_by_signatures(tmp_path, monkeypatch):
    # Handshake timeout of 1 s so the refused handshake doesn't slow the test.
    monkeypatch.setattr(core, "HANDSHAKE_TIMEOUT", 1)

    async def scenario():
        relay, proxy, alice, bob, inbox, infos = await setup(str(tmp_path), MitmProxy, insecure=False)
        try:
            await alice.start_chat("bob")
            ok = True
        except ConnectionError:
            ok = False
        await teardown(relay, proxy, alice, bob)
        return ok, infos

    ok, infos = asyncio.run(scenario())
    assert not ok
    assert any("SIG_FAIL" in i for i in infos)
    assert "SIG_FAIL" in read_events(tmp_path / "security-bob.jsonl")


def test_forged_identity_shows_different_safety_numbers(tmp_path):
    async def scenario():
        relay, proxy, alice, bob, inbox, _ = await setup(
            str(tmp_path), MitmProxy, insecure=False, forge_identity=True)
        await alice.start_chat("bob")   # first contact: TOFU accepts the attacker's key...
        numbers = alice.safety_number("bob"), bob.safety_number("alice")
        await teardown(relay, proxy, alice, bob)
        return numbers

    alice_sees, bob_sees = asyncio.run(scenario())
    assert alice_sees != bob_sees  # ...but comparing safety numbers exposes the attacker


# ---------------------------------------------------------------- replay
def test_replay_works_against_insecure_clients(tmp_path):
    async def scenario():
        relay, proxy, alice, bob, inbox, _ = await setup(
            str(tmp_path), ReplayProxy, insecure=True, copies=2, delay=0.2)
        await alice.start_chat("bob")
        await alice.send_chat("bob", "pay 100 to bob")
        received = [await asyncio.wait_for(inbox.get(), 5) for _ in range(3)]
        await teardown(relay, proxy, alice, bob)
        return received

    assert asyncio.run(scenario()) == [("alice", "pay 100 to bob")] * 3


def test_replay_is_rejected_by_secure_clients(tmp_path):
    async def scenario():
        relay, proxy, alice, bob, inbox, _ = await setup(
            str(tmp_path), ReplayProxy, insecure=False, copies=2, delay=0.2)
        await alice.start_chat("bob")
        await alice.send_chat("bob", "pay 100 to bob")
        first = await asyncio.wait_for(inbox.get(), 5)
        no_more = await nothing_arrives(inbox, 0.8)
        await teardown(relay, proxy, alice, bob)
        return first, no_more

    first, no_more = asyncio.run(scenario())
    assert first == ("alice", "pay 100 to bob") and no_more
    assert read_events(tmp_path / "security-bob.jsonl").count("REPLAY_OR_REORDER") == 2


# ---------------------------------------------------------------- tamper
def test_bit_flip_changes_amount_for_insecure_clients(tmp_path):
    async def scenario():
        relay, proxy, alice, bob, inbox, _ = await setup(str(tmp_path), TamperProxy, insecure=True)
        await alice.start_chat("bob")
        await alice.send_chat("bob", "pay 100 to bob")
        got = await asyncio.wait_for(inbox.get(), 5)
        await teardown(relay, proxy, alice, bob)
        return got

    assert asyncio.run(scenario()) == ("alice", "pay 900 to bob")


def test_bit_flip_is_detected_by_aes_gcm(tmp_path):
    async def scenario():
        relay, proxy, alice, bob, inbox, infos = await setup(str(tmp_path), TamperProxy, insecure=False)
        await alice.start_chat("bob")
        await alice.send_chat("bob", "pay 100 to bob")
        nothing = await nothing_arrives(inbox, 0.5)
        await teardown(relay, proxy, alice, bob)
        return nothing, infos

    nothing, infos = asyncio.run(scenario())
    assert nothing
    assert any("TAG_FAIL" in i for i in infos)
    assert "TAG_FAIL" in read_events(tmp_path / "security-bob.jsonl")
