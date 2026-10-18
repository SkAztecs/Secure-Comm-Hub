"""
relay_server.py
---------------
The relay server: it AUTHENTICATES users and ROUTES envelopes between them.

IMPORTANT DESIGN RULE:
    This file never imports a decrypt function and never sees a message key.
    It only reads the envelope fields "type", "from", "to".
    The chat text is inside "packet", which it cannot open
    -> that is what makes the encryption END-TO-END.

What happens to every new connection (Phase 2 order matters!):
    1. Firewall check (Pillar 3 blacklist)  -> blocked IPs are dropped before anything else
    2. TLS 1.3 handshake                    -> network can't see usernames or passwords
    3. HELLO within 10 s                    -> register or login (Argon2id + rate limit)
    4. Route envelopes by "to"              -> the server never decrypts

Every security-relevant event is written to logs/security.jsonl for Pillar 2.

Run (TLS on, the normal way):
    python scripts/make_certs.py --ip <this machine's IP>     (once)
    python -m server.relay_server --host 0.0.0.0 --port 9000
Run without TLS (attack demos only):
    python -m server.relay_server --no-tls
"""

import argparse
import asyncio
import logging
import os
import re
import ssl
import threading

from common.envelope import EnvelopeError, b64decode, make_envelope, parse_envelope
from common.framing import FrameError, FrameTooLarge, recv_frame, send_frame
from common.security_log import SecurityLogger
from common import tls
from server.auth import AuthError, LoginRateLimiter, UserStore
from server.firewall_hook import FirewallHook

log = logging.getLogger("relay")

# Usernames: 1-32 letters, digits, _ or -   (keeps logs, routing and signatures simple)
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# Message types the server is willing to forward between clients.
ROUTABLE_TYPES = {"KEY_INIT", "KEY_RESP", "CHAT", "FILE_CHUNK", "REKEY", "ACK"}

# How long a new connection has to send HELLO before we drop it (seconds).
HELLO_TIMEOUT = 10


class RelayServer:
    def __init__(self, host, port, user_store=None, ssl_context=None,
                 firewall=None, security_log=None):
        self.host = host
        self.port = port
        self.users = user_store or UserStore(":memory:")
        self.ssl_context = ssl_context          # None = no TLS (demo mode)
        self.firewall = firewall or FirewallHook()
        self.security = security_log or SecurityLogger("logs/security.jsonl")
        self.rate_limiter = LoginRateLimiter()
        # SQLite + Argon2 run in a worker thread (so hashing never freezes the server);
        # this lock makes sure only one thread touches the database at a time.
        self.db_lock = threading.Lock()

        # username -> asyncio.StreamWriter (the open connection to that user)
        self.clients = {}

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------
    async def start(self):
        """Start listening. Returns the asyncio Server object."""
        # NOTE: no ssl= here on purpose. We upgrade to TLS inside handle_connection,
        # AFTER the firewall check, so blocked IPs never even get a TLS handshake.
        self.server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        self.port = self.server.sockets[0].getsockname()[1]
        mode = "TLS 1.3" if self.ssl_context else "NO TLS (demo mode)"
        log.info("Relay server listening on %s:%s  [%s]", self.host, self.port, mode)
        return self.server

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    # ------------------------------------------------------------------
    # One task runs this function per connected client
    # ------------------------------------------------------------------
    async def handle_connection(self, reader, writer):
        peer_ip, peer_port = writer.get_extra_info("peername")[:2]
        username = None

        # ---- Step 1: Pillar 3 firewall check, before ANYTHING else ----
        if self.firewall.is_blocked(peer_ip):
            self.security.event("BLOCKED_CONNECTION", peer_ip, peer_port,
                                detail="IP is on the firewall blacklist")
            log.warning("BLOCKED %s:%s (blacklisted)", peer_ip, peer_port)
            writer.close()
            return

        log.info("CONNECT %s:%s", peer_ip, peer_port)
        try:
            # ---- Step 2: TLS 1.3 upgrade ----
            if self.ssl_context:
                try:
                    await asyncio.wait_for(writer.start_tls(self.ssl_context), timeout=HELLO_TIMEOUT)
                except (ssl.SSLError, asyncio.TimeoutError, ConnectionError, OSError) as error:
                    self.security.event("TLS_FAIL", peer_ip, peer_port, detail=str(error)[:200])
                    log.warning("TLS_FAIL %s:%s %s", peer_ip, peer_port, error)
                    return

            # ---- Step 3: the first frame MUST be a HELLO (login/register) ----
            first = await asyncio.wait_for(recv_frame(reader), timeout=HELLO_TIMEOUT)
            hello = parse_envelope(first)
            username = await self.authenticate(hello, writer, peer_ip, peer_port)
            if username is None:
                return  # authenticate() already sent the error and logged it

            # ---- Step 4: route everything else ----
            while True:
                data = await recv_frame(reader)
                envelope = parse_envelope(data)
                await self.route(username, envelope)

        except asyncio.TimeoutError:
            self.security.event("HANDSHAKE_TIMEOUT", peer_ip, peer_port,
                                detail=f"no HELLO within {HELLO_TIMEOUT}s")
            log.warning("HELLO_TIMEOUT from %s:%s", peer_ip, peer_port)
        except FrameTooLarge as error:
            self.security.event("FRAME_TOO_LARGE", peer_ip, peer_port, user=username,
                                detail=str(error))
            log.warning("FRAME_TOO_LARGE from %s (%s)", username, peer_ip)
        except FrameError as error:
            # Normal disconnects also land here ("Connection closed").
            log.info("Connection ended for %s (%s): %s", username, peer_ip, error)
        except EnvelopeError as error:
            self.security.event("MALFORMED_FRAME", peer_ip, peer_port, user=username,
                                detail=str(error))
            log.warning("MALFORMED_FRAME from %s (%s): %s", username, peer_ip, error)
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            log.info("Connection reset by %s (%s)", username, peer_ip)
        finally:
            # Always clean up: forget the user and close the socket.
            if username and self.clients.get(username) is writer:
                del self.clients[username]
                log.info("DISCONNECT %s", username)
            writer.close()

    # ------------------------------------------------------------------
    # HELLO = register or login
    # ------------------------------------------------------------------
    async def authenticate(self, hello, writer, peer_ip, peer_port):
        """
        HELLO envelope:
            {"type": "HELLO", "from": "alice", "mode": "login" | "register",
             "password": "...", "id_pub": "<base64 Ed25519 public key>"}
        Returns the username on success, None on failure.
        """
        username = hello.get("from", "")
        mode = hello.get("mode", "login")

        # Brute-force defence: a locked-out IP gets nothing.
        if self.rate_limiter.is_locked(peer_ip):
            self.security.event("LOGIN_LOCKOUT", peer_ip, peer_port, user=username,
                                detail="attempt while locked out")
            await self.send_error(writer, "Too many failed logins. Try again in a minute.")
            return None

        try:
            if hello.get("type") != "HELLO":
                raise AuthError("First message must be HELLO")
            if not USERNAME_PATTERN.match(username):
                raise AuthError("Invalid username (use 1-32 letters, digits, _ or -)")
            password = hello.get("password")
            if not isinstance(password, str) or not password:
                raise AuthError("Password missing")
            id_pub = b64decode(hello.get("id_pub", ""))
            if len(id_pub) != 32:
                raise AuthError("Identity key missing or wrong size")

            # Argon2 is slow on purpose -> run it in a worker thread.
            def check():
                with self.db_lock:
                    if mode == "register":
                        self.users.register(username, password, id_pub.hex())
                    else:
                        self.users.login(username, password, id_pub.hex())
            await asyncio.get_running_loop().run_in_executor(None, check)

            if username in self.clients:
                raise AuthError(f"User '{username}' is already online")

        except (AuthError, EnvelopeError) as error:
            locked_now = self.rate_limiter.record_failure(peer_ip)
            self.security.event("LOGIN_FAIL", peer_ip, peer_port, user=username or None,
                                detail=f"{mode}: {error}")
            if locked_now:
                self.security.event("LOGIN_LOCKOUT", peer_ip, peer_port, user=username or None,
                                    detail=f"{LoginRateLimiter.MAX_FAILURES} failures in "
                                           f"{LoginRateLimiter.WINDOW_SECONDS}s")
            log.warning("LOGIN_FAIL %s from %s: %s", username, peer_ip, error)
            await self.send_error(writer, str(error))
            return None

        self.rate_limiter.record_success(peer_ip)
        self.clients[username] = writer
        self.security.event("REGISTER_OK" if mode == "register" else "LOGIN_OK",
                            peer_ip, peer_port, user=username)
        log.info("%s ok for '%s'  (online: %s)", mode.upper(), username, sorted(self.clients))

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

        target_writer = self.clients.get(target)
        if target_writer is None:
            await self.send_error(self.clients[sender], f"User '{target}' is not online")
            return

        # Never trust the "from" field the client typed - it is replaced with the
        # name this (authenticated) connection logged in as. Stops spoofing.
        extra = {k: v for k, v in envelope.items() if k not in ("type", "from", "to")}
        await send_frame(target_writer, make_envelope(msg_type, sender, to=target, **extra))
        log.info("ROUTE %-8s %s -> %s", msg_type, sender, target)

    async def send_error(self, writer, reason: str):
        """Send an ERROR envelope back to a client."""
        try:
            await send_frame(writer, make_envelope("ERROR", "server", reason=reason))
        except (ConnectionError, FrameError, ssl.SSLError):
            pass


# ----------------------------------------------------------------------
# Command-line entry point
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Pillar 1 relay server")
    parser.add_argument("--host", default=os.getenv("RELAY_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("RELAY_PORT", "9000")))
    parser.add_argument("--cert-dir", default="certs", help="folder with server.pem / server.key")
    parser.add_argument("--no-tls", action="store_true", help="DEMO ONLY: plain TCP, no TLS")
    parser.add_argument("--db", default="data/users.db", help="SQLite user database")
    parser.add_argument("--blacklist", default="data/blacklist.txt", help="Pillar 3 blacklist file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    ssl_context = None
    if args.no_tls:
        log.warning("!!! TLS DISABLED - usernames and passwords travel in plain text. Demo only. !!!")
    else:
        cert = os.path.join(args.cert_dir, "server.pem")
        key = os.path.join(args.cert_dir, "server.key")
        if not (os.path.exists(cert) and os.path.exists(key)):
            raise SystemExit(f"No certificate in {args.cert_dir}/. "
                             "Run: python scripts/make_certs.py --ip <server IP>   (or use --no-tls)")
        ssl_context = tls.server_context(cert, key)

    async def run():
        relay = RelayServer(args.host, args.port,
                            user_store=UserStore(args.db),
                            ssl_context=ssl_context,
                            firewall=FirewallHook(args.blacklist),
                            security_log=SecurityLogger("logs/security.jsonl"))
        server = await relay.start()
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("Server stopped")


if __name__ == "__main__":
    main()
