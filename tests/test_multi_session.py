"""
Reproduces the bug Jai found on 2026-10-18:

    alice <-> bob session is active in alice's terminal,
    dhinakar starts a session with alice,
    alice types "hi dhina"  ->  it used to go to BOB (the active chat).

These tests check:
    1. Each session has its own keys, and a message to one peer never reaches another.
    2. The CLI does not silently keep sending to the old peer:
       @dhinakar <msg> and /switch dhinakar route to the right person.
"""

import argparse
import asyncio
import os

from client.cli_client import CliChat
from client.identity import Identity
from tests.helpers import PASSPHRASE, PASSWORD, connect, make_client, nothing_arrives, start_relay


async def start_three_users(tmp):
    relay = await start_relay(tmp)

    inboxes = {"bob": asyncio.Queue(), "dhinakar": asyncio.Queue()}
    bob = make_client(tmp, "bob", inboxes["bob"])
    dhina = make_client(tmp, "dhinakar", inboxes["dhinakar"])

    # alice uses the real CLI logic (without a keyboard).
    keys_dir = os.path.join(tmp, "keys")
    args = argparse.Namespace(name="alice", host="127.0.0.1", port=relay.port,
                              keys_dir=keys_dir, log_dir=tmp, insecure=False, register=True)
    alice_cli = CliChat(args, Identity.load_or_create("alice", PASSPHRASE, keys_dir),
                        PASSWORD, None)

    await alice_cli.client.connect("127.0.0.1", relay.port, PASSWORD, register=True)
    await connect(bob, relay)
    await connect(dhina, relay)
    return relay, alice_cli, bob, dhina, inboxes


def test_sessions_are_separate_and_messages_go_to_the_right_peer(tmp_path):
    async def scenario():
        relay, alice_cli, bob, dhina, inboxes = await start_three_users(str(tmp_path))

        # bob starts a session with alice -> it becomes alice's active chat
        await bob.start_chat("alice")
        await asyncio.sleep(0.1)
        assert alice_cli.active_peer == "bob"

        # dhinakar starts a session with alice -> alice's active chat STAYS bob
        await dhina.start_chat("alice")
        await asyncio.sleep(0.1)
        assert alice_cli.active_peer == "bob"

        # Two sessions, two different key sets.
        sessions = alice_cli.client.sessions
        assert sessions["bob"].ratchet.root_key != sessions["dhinakar"].ratchet.root_key

        # 1) "@dhinakar hi dhina" goes ONLY to dhinakar
        await alice_cli.handle_line("@dhinakar hi dhina")
        assert await asyncio.wait_for(inboxes["dhinakar"].get(), 2) == ("alice", "hi dhina")
        assert await nothing_arrives(inboxes["bob"])

        # 2) after /switch, plain text goes to dhinakar, not bob
        await alice_cli.handle_line("/switch dhinakar")
        assert alice_cli.active_peer == "dhinakar"
        await alice_cli.handle_line("second message")
        assert await asyncio.wait_for(inboxes["dhinakar"].get(), 2) == ("alice", "second message")
        assert await nothing_arrives(inboxes["bob"])

        # 3) switching back to bob works without a new handshake
        await alice_cli.handle_line("/switch bob")
        await alice_cli.handle_line("back to bob")
        assert await asyncio.wait_for(inboxes["bob"].get(), 2) == ("alice", "back to bob")
        assert await nothing_arrives(inboxes["dhinakar"])

        for c in (alice_cli.client, bob, dhina):
            await c.close()
        await relay.stop()

    asyncio.run(scenario())


def test_switch_to_unknown_peer_is_refused(tmp_path):
    async def scenario():
        relay, alice_cli, bob, dhina, inboxes = await start_three_users(str(tmp_path))
        await bob.start_chat("alice")
        await asyncio.sleep(0.1)
        await alice_cli.handle_line("/switch nobody")
        assert alice_cli.active_peer == "bob"  # unchanged
        for c in (alice_cli.client, bob, dhina):
            await c.close()
        await relay.stop()

    asyncio.run(scenario())


def test_bare_commands_use_active_chat_or_show_usage(tmp_path, capsys):
    """'/safety' alone = active chat; '/chat' alone = usage, not 'Unknown command'."""
    async def scenario():
        relay, alice_cli, bob, dhina, inboxes = await start_three_users(str(tmp_path))
        await bob.start_chat("alice")
        await asyncio.sleep(0.1)
        for line in ("/safety", "/chat", "/send bob", "/trust", "/switch", "/nonsense"):
            await alice_cli.handle_line(line)
        for c in (alice_cli.client, bob, dhina):
            await c.close()
        await relay.stop()
        return alice_cli.client.safety_number("bob")

    number = asyncio.run(scenario())
    out = capsys.readouterr().out
    assert f"Safety number with bob: {number}" in out
    assert "Usage: /chat <user>" in out
    assert "Usage: /send <user> <path to file>" in out and "C:\\Users\\me\\notes.pdf" in out
    assert "Usage: /trust <user>" in out and "Usage: /switch <user>" in out
    assert "Unknown command /nonsense" in out
