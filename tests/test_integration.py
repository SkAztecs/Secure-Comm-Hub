"""
End-to-end test: a real relay server + two real clients on localhost.
Also checks that the server only ever relays ciphertext.
"""

import asyncio

from client.client_core import ChatClient
from server.relay_server import RelayServer


def test_alice_and_bob_chat_through_relay():
    async def scenario():
        relay = RelayServer("127.0.0.1", 0)  # port 0 = pick any free port
        await relay.start()

        # Spy on everything the server forwards.
        forwarded = []
        original_route = relay.route

        async def spy_route(sender, envelope):
            forwarded.append(dict(envelope))
            await original_route(sender, envelope)
        relay.route = spy_route

        bob_inbox = asyncio.Queue()
        alice_inbox = asyncio.Queue()
        alice = ChatClient("alice", on_message=lambda p, t: alice_inbox.put_nowait((p, t)),
                           on_info=lambda t: None)
        bob = ChatClient("bob", on_message=lambda p, t: bob_inbox.put_nowait((p, t)),
                         on_info=lambda t: None)

        await alice.connect("127.0.0.1", relay.port)
        await bob.connect("127.0.0.1", relay.port)

        await alice.start_chat("bob")
        await alice.send_chat("bob", "top secret plan")
        got_bob = await asyncio.wait_for(bob_inbox.get(), 5)

        await bob.send_chat("alice", "roger that")
        got_alice = await asyncio.wait_for(alice_inbox.get(), 5)

        await alice.close()
        await bob.close()
        await relay.stop()
        return got_bob, got_alice, forwarded

    got_bob, got_alice, forwarded = asyncio.run(scenario())

    assert got_bob == ("alice", "top secret plan")
    assert got_alice == ("bob", "roger that")

    # The plaintext must never appear in anything the server handled.
    everything_server_saw = str(forwarded)
    assert "top secret plan" not in everything_server_saw
    assert "roger that" not in everything_server_saw
    assert any(e["type"] == "CHAT" and "packet" in e for e in forwarded)


def test_message_to_offline_user_gives_error():
    async def scenario():
        relay = RelayServer("127.0.0.1", 0)
        await relay.start()
        infos = []
        alice = ChatClient("alice", on_message=lambda p, t: None, on_info=infos.append)
        await alice.connect("127.0.0.1", relay.port)
        try:
            await alice.start_chat("ghost")
            failed = False
        except ConnectionError:
            failed = True
        await alice.close()
        await relay.stop()
        return failed, infos

    failed, infos = asyncio.run(scenario())
    assert failed
    assert any("not online" in i for i in infos)
