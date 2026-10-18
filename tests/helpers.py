"""
Shared helpers for tests: a relay server and logged-in clients, all using a
temporary folder for keys, databases and logs (so tests never touch real files).
"""

import asyncio
import os

from client.client_core import ChatClient
from client.identity import Identity, KnownPeers
from common.security_log import SecurityLogger
from server.auth import UserStore
from server.firewall_hook import FirewallHook
from server.relay_server import RelayServer

PASSWORD = "correct-horse-battery"
PASSPHRASE = "key-passphrase-123"


async def start_relay(tmp, ssl_context=None):
    relay = RelayServer(
        "127.0.0.1", 0,
        user_store=UserStore(":memory:"),
        ssl_context=ssl_context,
        firewall=FirewallHook(os.path.join(tmp, "blacklist.txt")),
        security_log=SecurityLogger(os.path.join(tmp, "server-security.jsonl")))
    await relay.start()
    return relay


def make_client(tmp, name, inbox=None, infos=None, insecure=False):
    """A ChatClient with its own identity in tmp/keys and its own security log."""
    keys_dir = os.path.join(tmp, "keys")
    identity = Identity.load_or_create(name, PASSPHRASE, keys_dir)

    def on_message(peer, text):
        if inbox is not None:
            inbox.put_nowait((peer, text))

    def on_info(text):
        if infos is not None:
            infos.append(text)

    return ChatClient(name, identity, KnownPeers(name, keys_dir), insecure=insecure,
                      on_message=on_message, on_info=on_info,
                      security_log=SecurityLogger(os.path.join(tmp, f"security-{name}.jsonl")))


async def connect(client, relay, register=True, ssl_context=None, password=PASSWORD):
    await client.connect("127.0.0.1", relay.port, password,
                         register=register, ssl_context=ssl_context)


async def nothing_arrives(queue, seconds=0.3):
    try:
        await asyncio.wait_for(queue.get(), seconds)
        return False
    except asyncio.TimeoutError:
        return True


def read_events(path):
    """All event names in a JSONL security log."""
    import json
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line)["event"] for line in f if line.strip()]
