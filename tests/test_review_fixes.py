"""
Regression tests for the issues found in the independent code review (2026-10-18).
Each test reproduces the original attack and checks it no longer works.
"""

import asyncio
import os
import time

import pytest

import client.client_core as core
from client.file_transfer import MAX_ACTIVE_PER_SENDER, FileTransferError, IncomingFiles, pack
from client.session import Session
from common.envelope import b64encode, make_envelope
from common.framing import send_frame
from tests.helpers import connect, make_client, start_relay


# ---------------------------------------------------------------- C1 path traversal via id
def test_crafted_transfer_id_cannot_escape_downloads(tmp_path):
    downloads = tmp_path / "downloads"
    receiver = IncomingFiles(str(downloads))
    receiver.handle("mallory", pack({"kind": "start", "id": "/../../../pwned", "name": "x",
                                     "size": 5, "chunks": 1, "sha256": "0"}))
    receiver.handle("mallory", pack({"kind": "chunk", "id": "/../../../pwned", "index": 0}, b"evil!"))
    assert not (tmp_path / "pwned.part").exists()
    assert not any("pwned" in name for name in os.listdir(tmp_path))
    # the one temporary file must be directly inside the downloads folder
    assert len(list(downloads.glob("*.part"))) == 1


# ---------------------------------------------------------------- C2 malformed headers
# Short ids: without them pytest puts the whole 100,000-byte input into the test
# name, and Windows refuses environment variables longer than 32,767 characters.
@pytest.mark.parametrize("plaintext", [b"[1]\n", b'{"kind":"start","size":null}\n',
                                       b'{"kind":"start","size":1,"chunks":[]}\n',
                                       b"[" * 100000 + b"\n"],
                         ids=["list-not-object", "size-null", "chunks-list", "deep-nesting"])
def test_malformed_file_headers_raise_cleanly(tmp_path, plaintext):
    receiver = IncomingFiles(str(tmp_path))
    with pytest.raises(FileTransferError):
        receiver.handle("mallory", plaintext)


def test_hostile_file_piece_does_not_kill_the_client(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        inbox, infos = asyncio.Queue(), []
        mallory = make_client(str(tmp_path), "mallory")
        bob = make_client(str(tmp_path), "bob", inbox, infos)
        await connect(mallory, relay)
        await connect(bob, relay)
        await mallory.start_chat("bob")
        for evil in (b"[1]\n", b'{"kind":"start","size":null}\n', b"[" * 30000 + b"\n"):
            await mallory.send_encrypted("bob", evil, 0x11, "FILE_CHUNK")
        await mallory.send_chat("bob", "still alive?")
        got = await asyncio.wait_for(inbox.get(), 5)
        await mallory.close()
        await bob.close()
        await relay.stop()
        return got

    assert asyncio.run(scenario()) == ("mallory", "still alive?")


# ---------------------------------------------------------------- M1 message right after KEY_RESP
def test_first_message_right_behind_key_resp_is_not_lost(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        inbox = asyncio.Queue()
        alice = make_client(str(tmp_path), "alice", inbox)
        bob = make_client(str(tmp_path), "bob")
        await connect(alice, relay)
        await connect(bob, relay)

        # bob answers KEY_INIT and IMMEDIATELY sends a message in the same breath.
        original = bob.handle_key_init

        async def answer_and_talk(sender, envelope):
            await original(sender, envelope)
            await bob.send_chat(sender, "instant reply")
        bob.handle_key_init = answer_and_talk

        await alice.start_chat("bob")
        got = await asyncio.wait_for(inbox.get(), 5)
        await alice.close()
        await bob.close()
        await relay.stop()
        return got

    assert asyncio.run(scenario()) == ("bob", "instant reply")


# ---------------------------------------------------------------- M2 replayed KEY_INIT
def test_replayed_key_init_is_refused_and_session_survives(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "HANDSHAKE_TIMEOUT", 1)

    async def scenario():
        relay = await start_relay(str(tmp_path))
        captured = []
        original_route = relay.route

        async def recording_route(sender, envelope):     # a "malicious relay"
            if envelope.get("type") == "KEY_INIT":
                captured.append(dict(envelope))
            await original_route(sender, envelope)
        relay.route = recording_route

        inbox, infos = asyncio.Queue(), []
        alice = make_client(str(tmp_path), "alice")
        bob = make_client(str(tmp_path), "bob", inbox, infos)
        await connect(alice, relay)
        await connect(bob, relay)
        await alice.start_chat("bob")
        working = bob.sessions["alice"]

        # The relay replays alice's old, validly signed KEY_INIT to bob.
        old = captured[0]
        extra = {k: v for k, v in old.items() if k not in ("type", "from", "to")}
        await send_frame(relay.clients["bob"], make_envelope("KEY_INIT", "alice", to="bob", **extra))
        await asyncio.sleep(0.3)

        same_session = bob.sessions["alice"] is working
        await alice.send_chat("bob", "after the replay")
        got = await asyncio.wait_for(inbox.get(), 5)
        await alice.close()
        await bob.close()
        await relay.stop()
        return same_session, got, infos

    same_session, got, infos = asyncio.run(scenario())
    assert same_session
    assert got == ("alice", "after the replay")
    assert any("replayed" in i for i in infos)


def test_stale_key_init_is_refused(tmp_path):
    client = make_client(str(tmp_path), "bob")
    old = {"pub": os.urandom(32), "ts": int(time.time() - 3600).to_bytes(8, "big")}
    with pytest.raises(core.HandshakeRefused):
        client.check_fresh("alice", old)


# ---------------------------------------------------------------- M3 resource exhaustion
def test_too_many_parallel_transfers_are_refused(tmp_path):
    receiver = IncomingFiles(str(tmp_path))
    results = [receiver.handle("mallory", pack({"kind": "start", "id": str(i), "name": "f",
                                                "size": 10, "chunks": 1, "sha256": "0"}))
               for i in range(MAX_ACTIVE_PER_SENDER + 3)]
    assert sum(r[0] == "info" for r in results) == MAX_ACTIVE_PER_SENDER
    assert len(list(tmp_path.glob("*.part"))) == MAX_ACTIVE_PER_SENDER
    # duplicate id refused too
    dup = receiver.handle("mallory", pack({"kind": "start", "id": "0", "name": "f",
                                           "size": 10, "chunks": 1, "sha256": "0"}))
    assert dup[0] == "failed"
    receiver.cancel_from("mallory")
    assert list(tmp_path.glob("*.part")) == []


# ---------------------------------------------------------------- L1 bad kem_ct fails fast
def test_bad_kem_ciphertext_fails_immediately():
    alice = Session("bob", is_initiator=True)
    reply = Session("alice", is_initiator=False).respond(alice.init_fields())
    reply["kem_ct"] = b"short"
    with pytest.raises(ValueError):
        alice.finish(reply)   # client_core turns this into HandshakeRefused right away
