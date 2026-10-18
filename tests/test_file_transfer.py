"""
Phase 3: end-to-end encrypted file transfer.
"""

import asyncio
import hashlib
import os

import pytest

from client.file_transfer import CHUNK_SIZE, IncomingFiles, pack, prepare_outgoing, safe_filename
from tests.helpers import connect, make_client, start_relay


def make_file(path, size):
    data = os.urandom(size)
    with open(path, "wb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


def test_file_arrives_intact_and_server_never_sees_it(tmp_path):
    source = tmp_path / "report.pdf"
    original_hash = make_file(source, 3 * CHUNK_SIZE + 1234)   # 4 chunks, last one partial
    downloads = tmp_path / "bob_downloads"

    async def scenario():
        relay = await start_relay(str(tmp_path))
        seen_by_server = []
        original_route = relay.route

        async def spy(sender, envelope):
            seen_by_server.append(str(envelope))
            await original_route(sender, envelope)
        relay.route = spy

        infos = []
        alice = make_client(str(tmp_path), "alice")
        bob = make_client(str(tmp_path), "bob", infos=infos)
        bob.incoming_files = IncomingFiles(str(downloads))
        await connect(alice, relay)
        await connect(bob, relay)
        await alice.start_chat("bob")
        await alice.send_file("bob", str(source))
        for _ in range(50):
            if any("Received file" in i for i in infos):
                break
            await asyncio.sleep(0.1)
        await alice.close()
        await bob.close()
        await relay.stop()
        return infos, seen_by_server

    infos, seen_by_server = asyncio.run(scenario())
    received = downloads / "report.pdf"
    assert received.exists()
    assert hashlib.sha256(received.read_bytes()).hexdigest() == original_hash
    assert any("SHA-256 verified" in i for i in infos)
    # The file name is only inside the encrypted packets - the server never saw it.
    assert not any("report.pdf" in e for e in seen_by_server)
    assert sum('"FILE_CHUNK"' in e or "'FILE_CHUNK'" in e for e in seen_by_server) == 6  # start + 4 + end


def test_corrupted_file_is_discarded(tmp_path):
    source = tmp_path / "a.bin"
    make_file(source, 1000)
    info, pieces = prepare_outgoing(str(source))
    pieces = list(pieces)
    receiver = IncomingFiles(str(tmp_path / "in"))

    # Tamper with the announced hash (as if the plaintext had been altered).
    import json
    header, _, data = pieces[0].partition(b"\n")
    fake = json.loads(header)
    fake["sha256"] = "0" * 64
    pieces[0] = pack(fake)

    results = [receiver.handle("alice", p) for p in pieces]
    assert results[-1][0] == "failed" and "SHA-256" in results[-1][1]
    assert os.listdir(tmp_path / "in") == []          # nothing kept, no .part left


def test_path_traversal_names_are_neutralised():
    assert safe_filename("../../windows/system32/evil.dll") == "evil.dll"
    assert safe_filename("..\\..\\boot.ini") == "boot.ini"
    assert safe_filename("....") == "file"
    assert "/" not in safe_filename("a/b/c.txt")


def test_oversized_file_is_refused(tmp_path):
    from client import file_transfer
    receiver = IncomingFiles(str(tmp_path))
    kind, _ = receiver.handle("alice", pack({"kind": "start", "id": "x",
                                             "size": file_transfer.MAX_FILE_SIZE + 1}))
    assert kind == "failed"


def test_same_name_does_not_overwrite(tmp_path):
    source = tmp_path / "notes.txt"
    make_file(source, 10)
    receiver = IncomingFiles(str(tmp_path / "in"))
    for _ in range(2):
        _info, pieces = prepare_outgoing(str(source))
        results = [receiver.handle("alice", p) for p in pieces]
    assert sorted(os.listdir(tmp_path / "in")) == ["notes (1).txt", "notes.txt"]
