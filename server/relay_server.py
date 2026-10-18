"""
relay_server.py
---------------
The relay server: it ROUTES envelopes between clients and nothing more.

IMPORTANT DESIGN RULE:
    This file never imports a decrypt function and never sees a key.
    It only reads the envelope fields "type", "from", "to".
    The chat text is inside "packet", which it cannot open.
    -> that is what makes the encryption END-TO-END.

How it works:
    1. A client connects and sends HELLO with its username.
    2. We remember   username -> connection   in a dictionary.
    3. Every later envelope has a "to" field; we forward it to that user.
    4. If "to" is offline, we send back an ERROR envelope.

Run:
    python -m server.relay_server --host 0.0.0.0 --port 9000
"""

import argparse
import asyncio
import logging
import os
import re

from common.envelope import EnvelopeError, make_envelope, parse_envelope
from common.framing import FrameError, recv_frame, send_frame

log = logging.getLogger("relay")

# Usernames: 1-32 letters, digits, _ or -   (keeps logs and routing simple)
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# Message types the server is willing to forward between clients.
ROUTABLE_TYPES = {"KEY_INIT", "KEY_RESP", "CHAT", "FILE_CHUNK", "REKEY", "ACK"}

# How long a new connection has to send HELLO before we drop it (seconds).
HELLO_TIMEOUT = 10


class RelayServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        # username -> asyncio.StreamWriter (the open connection to that user)
        self.clients = {}

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------
    async def start(self):
        """Start listening. Returns the asyncio Server object."""
        self.server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        # If port 0 was given, the OS picked a free port - read it back.
        self.port = self.server.sockets[0].getsockname()[1]
        log.info("Relay server listening on %s:%s", self.host, self.port)
        return self.server

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    # ------------------------------------------------------------------
    # One task runs this function per connected client
    # ------------------------------------------------------------------
    async def handle_connection(self, reader, writer):
        peer_ip, peer_port = writer.get_extra_info("peername")[:2]
        log.info("CONNECT %s:%s", peer_ip, peer_port)

        # Phase 2 hook: Pillar 3 firewall check goes HERE, before anything else.
        # if firewall_hook.is_blocked(peer_ip): writer.close(); return

        username = None
        try:
            # ---- Step 1: the first frame MUST be a HELLO ----
            first = await asyncio.wait_for(recv_frame(reader), timeout=HELLO_TIMEOUT)
            hello = parse_envelope(first)
            username = await self.register(hello, writer)
            if username is None:
                return  # register() already sent the error

            # ---- Step 2: route everything else ----
            while True:
                data = await recv_frame(reader)
                envelope = parse_envelope(data)
                await self.route(username, envelope)

        except asyncio.TimeoutError:
            log.warning("HELLO_TIMEOUT from %s:%s", peer_ip, peer_port)
        except FrameError as error:
            # Normal disconnects also land here ("Connection closed").
            log.info("Frame/connection ended for %s (%s): %s", username, peer_ip, error)
        except EnvelopeError as error:
            log.warning("MALFORMED_FRAME from %s (%s): %s", username, peer_ip, error)
        except (ConnectionResetError, BrokenPipeError):
            log.info("Connection reset by %s (%s)", username, peer_ip)
        finally:
            # Always clean up: forget the user and close the socket.
            if username and self.clients.get(username) is writer:
                del self.clients[username]
                log.info("DISCONNECT %s", username)
            writer.close()

    # ------------------------------------------------------------------
    # HELLO handling
    # ------------------------------------------------------------------
    async def register(self, hello: dict, writer):
        """Check the HELLO envelope and remember this user. Returns username or None."""
        username = hello.get("from", "")

        if hello.get("type") != "HELLO":
            await self.send_error(writer, "First message must be HELLO")
            return None

        if not USERNAME_PATTERN.match(username):
            await self.send_error(writer, "Invalid username (use 1-32 letters, digits, _ or -)")
            return None

        if username in self.clients:
            await self.send_error(writer, f"Username '{username}' is already online")
            return None

        self.clients[username] = writer
        log.info("HELLO registered user '%s'  (online: %s)", username, sorted(self.clients))

        # Tell the client it is in, and who else is online.
        await send_frame(writer, make_envelope("WELCOME", "server", to=username,
                                               online=sorted(self.clients)))
        return username

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    async def route(self, sender: str, envelope: dict):
        """Forward one envelope to its 'to' user."""
        msg_type = envelope.get("type")
        target = envelope.get("to")

        # A client asking "who is online?"
        if msg_type == "WHO":
            await send_frame(self.clients[sender],
                             make_envelope("WHO", "server", to=sender, online=sorted(self.clients)))
            return

        if msg_type not in ROUTABLE_TYPES:
            await self.send_error(self.clients[sender], f"Unknown message type: {msg_type}")
            return

        # Never trust the "from" field the client typed - overwrite it with
        # the name this connection actually registered with (stops spoofing).
        envelope["from"] = sender

        target_writer = self.clients.get(target)
        if target_writer is None:
            await self.send_error(self.clients[sender], f"User '{target}' is not online")
            return

        # Forward the envelope exactly as JSON. We do NOT look inside "packet".
        forwarded = make_envelope(msg_type, sender, to=target,
                                  **{k: v for k, v in envelope.items()
                                     if k not in ("type", "from", "to")})
        await send_frame(target_writer, forwarded)
        log.info("ROUTE %-8s %s -> %s", msg_type, sender, target)

    async def send_error(self, writer, reason: str):
        """Send an ERROR envelope back to a client."""
        try:
            await send_frame(writer, make_envelope("ERROR", "server", reason=reason))
        except (ConnectionError, FrameError):
            pass


# ----------------------------------------------------------------------
# Command-line entry point
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Pillar 1 relay server")
    parser.add_argument("--host", default=os.getenv("RELAY_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("RELAY_PORT", "9000")))
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    async def run():
        relay = RelayServer(args.host, args.port)
        server = await relay.start()
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("Server stopped")


if __name__ == "__main__":
    main()
