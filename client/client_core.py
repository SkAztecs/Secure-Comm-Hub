"""
client_core.py
--------------
All the networking + crypto logic of a client, with NO user interface.
The CLI client and the Tkinter GUI both reuse this class.

The UI gives us callback functions:
    on_message(peer, text)  -> a decrypted chat message arrived
    on_info(text)           -> status / error text to show the user
    on_session(peer)        -> someone ELSE started an encrypted session with us
                               (optional; lets the UI add that person to its chat list)

Usage (inside asyncio):
    client = ChatClient("alice", on_message=..., on_info=...)
    await client.connect("127.0.0.1", 9000)
    await client.start_chat("bob")
    await client.send_chat("bob", "hello!")
"""

import asyncio

from cryptography.exceptions import InvalidTag

from client.session import Session, SessionError
from common.envelope import (EnvelopeError, b64decode, b64encode,
                             make_envelope, parse_envelope)
from common.framing import FrameError, recv_frame, send_frame
from common.packet import PacketError

HANDSHAKE_TIMEOUT = 10  # seconds to wait for KEY_RESP


class ChatClient:
    def __init__(self, username, on_message=None, on_info=None, on_session=None):
        self.username = username
        self.on_session = on_session or (lambda peer: None)
        self.on_message = on_message or (lambda peer, text: print(f"[{peer}] {text}"))
        self.on_info = on_info or (lambda text: print(f"* {text}"))

        self.reader = None
        self.writer = None
        self.sessions = {}            # peer name -> Session
        self.pending_handshakes = {}  # peer name -> asyncio.Future (waiting for KEY_RESP)
        self.receive_task = None
        self.welcome = asyncio.Event()  # set when the server accepts our HELLO

    # ------------------------------------------------------------------
    # Connect / disconnect
    # ------------------------------------------------------------------
    async def connect(self, host: str, port: int) -> None:
        """Open the TCP connection, send HELLO, start the receive loop."""
        self.reader, self.writer = await asyncio.open_connection(host, port)
        await send_frame(self.writer, make_envelope("HELLO", self.username))

        # Read incoming frames in the background from now on.
        self.receive_task = asyncio.create_task(self.receive_loop())

        # Wait until the server says WELCOME (or the loop ends with an error).
        try:
            await asyncio.wait_for(self.welcome.wait(), timeout=10)
        except asyncio.TimeoutError:
            raise ConnectionError("Server did not accept HELLO")

    async def close(self) -> None:
        if self.receive_task:
            self.receive_task.cancel()
        if self.writer:
            self.writer.close()

    # ------------------------------------------------------------------
    # Starting a chat (we are the INITIATOR)
    # ------------------------------------------------------------------
    async def start_chat(self, peer: str) -> None:
        """Run the key exchange with `peer`. Returns when keys are ready."""
        if peer == self.username:
            raise ValueError("You cannot chat with yourself")

        session = Session(peer, is_initiator=True)
        self.sessions[peer] = session

        # A Future is a "box" that receive_loop fills when KEY_RESP arrives.
        future = asyncio.get_running_loop().create_future()
        self.pending_handshakes[peer] = future

        await send_frame(self.writer, make_envelope(
            "KEY_INIT", self.username, to=peer, pub=b64encode(session.my_public)))

        try:
            await asyncio.wait_for(future, timeout=HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError:
            self.sessions.pop(peer, None)
            raise ConnectionError(f"HANDSHAKE_TIMEOUT: {peer} did not answer")
        finally:
            self.pending_handshakes.pop(peer, None)

        self.on_info(f"Encrypted session with {peer} ready (fingerprint {session.fingerprint()})")

    # ------------------------------------------------------------------
    # Sending a message
    # ------------------------------------------------------------------
    async def send_chat(self, peer: str, text: str) -> None:
        """Encrypt `text` for `peer` and send it through the relay."""
        session = self.sessions.get(peer)
        if session is None or not session.ready:
            raise SessionError(f"No encrypted session with {peer}. Use /chat {peer} first.")

        packet = session.encrypt_message(text)
        await send_frame(self.writer, make_envelope(
            "CHAT", self.username, to=peer, packet=b64encode(packet)))

    async def ask_who(self) -> None:
        """Ask the server who is online (answer arrives via on_info)."""
        await send_frame(self.writer, make_envelope("WHO", self.username))

    # ------------------------------------------------------------------
    # Receive loop: runs forever in the background
    # ------------------------------------------------------------------
    async def receive_loop(self) -> None:
        try:
            while True:
                data = await recv_frame(self.reader)
                try:
                    envelope = parse_envelope(data)
                    await self.handle_envelope(envelope)
                except (EnvelopeError, PacketError, SessionError, InvalidTag, ValueError) as error:
                    # One bad message must never crash the client.
                    name = "TAG_FAIL (message was tampered with)" if isinstance(error, InvalidTag) else str(error)
                    self.on_info(f"Rejected a message: {name}")
        except FrameError:
            self.on_info("Disconnected from server")
        except asyncio.CancelledError:
            pass

    async def handle_envelope(self, envelope: dict) -> None:
        msg_type = envelope.get("type")
        sender = envelope.get("from")

        if msg_type == "WELCOME":
            self.welcome.set()
            self.on_info(f"Connected as {self.username}. Online: {', '.join(envelope.get('online', []))}")

        elif msg_type == "WHO":
            self.on_info(f"Online: {', '.join(envelope.get('online', []))}")

        elif msg_type == "ERROR":
            self.on_info(f"Server error: {envelope.get('reason')}")
            # If a handshake was waiting on an offline user, fail it now.
            for future in self.pending_handshakes.values():
                if not future.done():
                    future.set_exception(ConnectionError(envelope.get("reason")))

        elif msg_type == "KEY_INIT":
            # Someone wants to chat with us -> we are the RESPONDER.
            session = Session(sender, is_initiator=False)
            session.complete(b64decode(envelope["pub"]))
            self.sessions[sender] = session
            await send_frame(self.writer, make_envelope(
                "KEY_RESP", self.username, to=sender, pub=b64encode(session.my_public)))
            self.on_info(f"{sender} started an encrypted session (fingerprint {session.fingerprint()})")
            self.on_session(sender)

        elif msg_type == "KEY_RESP":
            session = self.sessions.get(sender)
            future = self.pending_handshakes.get(sender)
            if session is None or future is None:
                raise SessionError(f"Unexpected KEY_RESP from {sender}")
            session.complete(b64decode(envelope["pub"]))
            if not future.done():
                future.set_result(True)

        elif msg_type == "CHAT":
            session = self.sessions.get(sender)
            if session is None or not session.ready:
                raise SessionError(f"CHAT from {sender} but no session exists")
            text = session.decrypt_message(b64decode(envelope["packet"]))
            self.on_message(sender, text)

        else:
            self.on_info(f"Ignoring unknown message type {msg_type}")
