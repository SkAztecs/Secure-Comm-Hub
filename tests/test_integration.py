"""
End-to-end test: a real relay server + two real clients on localhost.
Also checks that the server only ever relays ciphertext.
"""

import asyncio

from tests.helpers import connect, make_client, start_relay


def test_alice_and_bob_chat_through_relay(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))

        # Spy on everything the server forwards.
        forwarded = []
        original_route = relay.route

        async def spy_route(sender, envelope):
            forwarded.append(dict(envelope))
            await original_route(sender, envelope)
        relay.route = spy_route

        bob_inbox, alice_inbox = asyncio.Queue(), asyncio.Queue()
        alice = make_client(str(tmp_path), "alice", alice_inbox)
        bob = make_client(str(tmp_path), "bob", bob_inbox)
        await connect(alice, relay)
        await connect(bob, relay)

        await alice.start_chat("bob")
        await alice.send_chat("bob", "top secret plan")
        got_bob = await asyncio.wait_for(bob_inbox.get(), 5)

        await bob.send_chat("alice", "roger that")
        got_alice = await asyncio.wait_for(alice_inbox.get(), 5)

        # Both sides compute the same safety number.
        same_number = alice.safety_number("bob") == bob.safety_number("alice")

        await alice.close()
        await bob.close()
        await relay.stop()
        return got_bob, got_alice, forwarded, same_number

    got_bob, got_alice, forwarded, same_number = asyncio.run(scenario())

    assert got_bob == ("alice", "top secret plan")
    assert got_alice == ("bob", "roger that")
    assert same_number

    # The plaintext must never appear in anything the server handled.
    everything_server_saw = str(forwarded)
    assert "top secret plan" not in everything_server_saw
    assert "roger that" not in everything_server_saw
    assert any(e["type"] == "CHAT" and "packet" in e for e in forwarded)


def test_message_to_offline_user_gives_error(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        infos = []
        alice = make_client(str(tmp_path), "alice", infos=infos)
        await connect(alice, relay)
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
