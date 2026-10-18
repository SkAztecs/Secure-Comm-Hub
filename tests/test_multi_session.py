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

from client.cli_client import CliChat
from client.client_core import ChatClient
from server.relay_server import RelayServer


async def start_three_users():
    relay = RelayServer("127.0.0.1", 0)
    await relay.start()

    inboxes = {"bob": asyncio.Queue(), "dhinakar": asyncio.Queue()}
    bob = ChatClient("bob", on_message=lambda p, t: inboxes["bob"].put_nowait((p, t)),
                     on_info=lambda t: None)
    dhina = ChatClient("dhinakar", on_message=lambda p, t: inboxes["dhinakar"].put_nowait((p, t)),
                       on_info=lambda t: None)

    # alice uses the real CLI logic (without a keyboard).
    args = argparse.Namespace(name="alice", host="127.0.0.1", port=relay.port)
    alice_cli = CliChat(args)

    await alice_cli.client.connect("127.0.0.1", relay.port)
    await bob.connect("127.0.0.1", relay.port)
    await dhina.connect("127.0.0.1", relay.port)
    return relay, alice_cli, bob, dhina, inboxes


async def nothing_arrives(queue, seconds=0.3):
    try:
        await asyncio.wait_for(queue.get(), seconds)
        return False
    except asyncio.TimeoutError:
        return True


def test_sessions_are_separate_and_messages_go_to_the_right_peer():
    async def scenario():
        relay, alice_cli, bob, dhina, inboxes = await start_three_users()

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
        assert sessions["bob"].send_key != sessions["dhinakar"].send_key

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


def test_switch_to_unknown_peer_is_refused():
    async def scenario():
        relay, alice_cli, bob, dhina, inboxes = await start_three_users()
        await bob.start_chat("alice")
        await asyncio.sleep(0.1)
        await alice_cli.handle_line("/switch nobody")
        assert alice_cli.active_peer == "bob"  # unchanged
        for c in (alice_cli.client, bob, dhina):
            await c.close()
        await relay.stop()

    asyncio.run(scenario())
