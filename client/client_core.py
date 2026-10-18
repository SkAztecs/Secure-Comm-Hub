"""
client_core.py
--------------
All the networking + crypto logic of a client, with NO user interface.
The CLI client and the Tkinter GUI both reuse this class.

The UI gives us callback functions:
    on_message(peer, text)  -> a decrypted chat message arrived
    on_info(text)           -> status / warning text to show the user
    on_session(peer)        -> someone ELSE started an encrypted session with us

Phase 2 security in this file:
    - HELLO carries the password (protected by TLS) and our identity public key
    - KEY_INIT / KEY_RESP are SIGNED with our Ed25519 identity key and the peer's
      signature is VERIFIED  -> a man-in-the-middle can't swap ephemeral keys
    - Trust on first use: a peer's identity key is saved the first time; if it
      ever changes we refuse the session until the user runs /trust
    - Automatic rekey after 1000 messages or 1 hour
    - A session is closed after 3 tampered (TAG_FAIL) packets
    - Every security event is written to logs/security-<username>.jsonl

Usage (inside asyncio):
    identity = Identity.load_or_create("alice", "key passphrase")
    client = ChatClient("alice", identity, KnownPeers("alice"))
    await client.connect("127.0.0.1", 9000, password="...", ssl_context=ctx)
    await client.start_chat("bob")
    await client.send_chat("bob", "hello!")
"""

import asyncio
import struct
import time
from collections import deque

from cryptography.exceptions import InvalidTag

import os

from client.file_transfer import IncomingFiles, prepare_outgoing
from client.identity import KnownPeers
from client.session import Session, SessionError
from common import crypto_utils
from common.envelope import (EnvelopeError, b64decode, b64encode,
                             make_envelope, parse_envelope)
from common.framing import FrameError, recv_frame, send_frame
from common.message_types import CHAT, FILE_CHUNK
from common.handshake import (INIT_FIELDS, MAX_CLOCK_SKEW, RESP_FIELDS, init_transcript,
                              resp_transcript)
from common.packet import PacketError
from common.security_log import SecurityLogger

HANDSHAKE_TIMEOUT = 10  # seconds to wait for KEY_RESP


class HandshakeRefused(Exception):
    """The peer's signature or identity key failed our checks."""


class ChatClient:
    def __init__(self, username, identity, known_peers=None, insecure=False, pq=True,
                 on_message=None, on_info=None, on_session=None, security_log=None,
                 downloads_dir=None):
        self.username = username
        self.identity = identity                       # our Ed25519 identity (client/identity.py)
        self.known_peers = known_peers or KnownPeers(username)
        self.insecure = insecure                       # DEMO ONLY: skip all Phase 2 checks
        self.pq = pq and crypto_utils.HAS_MLKEM        # offer the post-quantum hybrid handshake
        self.pq_missing = pq and not crypto_utils.HAS_MLKEM

        self.on_message = on_message or (lambda peer, text: print(f"[{peer}] {text}"))
        self.on_info = on_info or (lambda text: print(f"* {text}"))
        self.on_session = on_session or (lambda peer: None)
        self.security = security_log or SecurityLogger(f"logs/security-{username}.jsonl")

        self.reader = None
        self.writer = None
        self.sessions = {}            # peer -> Session that is READY to use
        self.pending = {}             # peer -> (Session, Future) while we wait for KEY_RESP
        self.untrusted_keys = {}      # peer -> new identity key we refused (see /trust)
        self.seen_init_keys = deque(maxlen=1000)   # recent KEY_INIT ephemeral keys (replay check)
        # Received files are saved in downloads/<username>/
        self.incoming_files = IncomingFiles(downloads_dir or os.path.join("downloads", username))
        self.receive_task = None
        self.welcome = asyncio.Event()
        self.connect_error = None

    # ==================================================================
    # Connect / disconnect
    # ==================================================================
    async def connect(self, host, port, password, register=False, ssl_context=None):
        """
        Open the connection (TLS if ssl_context is given), send HELLO, start the
        receive loop. Raises ConnectionError if the server refuses us.
        """
        if ssl_context is not None:
            # server_hostname is checked against the certificate (localhost / the IP).
            self.reader, self.writer = await asyncio.open_connection(
                host, port, ssl=ssl_context, server_hostname=host)
        else:
            self.reader, self.writer = await asyncio.open_connection(host, port)

        try:
            await send_frame(self.writer, make_envelope(
                "HELLO", self.username,
                mode="register" if register else "login",
                password=password,
                id_pub=b64encode(self.identity.public_bytes)))
        except OSError as error:
            # e.g. a TLS server resetting a plain-TCP client (Windows: WinError 10054)
            raise ConnectionError(f"Server closed the connection: {error}") from error

        self.receive_task = asyncio.create_task(self.receive_loop())

        try:
            await asyncio.wait_for(self.welcome.wait(), timeout=15)
        except asyncio.TimeoutError:
            raise ConnectionError("Server did not answer HELLO")
        if self.connect_error:
            raise ConnectionError(self.connect_error)

    async def close(self):
        if self.receive_task:
            self.receive_task.cancel()
        if self.writer:
            try:
                self.writer.close()
            except OSError:
                pass   # already reset by the other side (common on Windows)

    # ==================================================================
    # Starting a chat (we are the INITIATOR)
    # ==================================================================
    async def start_chat(self, peer: str) -> None:
        """Run the signed key exchange with `peer`. Returns when keys are ready."""
        if peer == self.username:
            raise ValueError("You cannot chat with yourself")

        # A handshake with this peer is already running -> just wait for it.
        if peer in self.pending:
            await self.pending[peer][1]
            return

        session = Session(peer, is_initiator=True, insecure=self.insecure, pq=self.pq)
        future = asyncio.get_running_loop().create_future()
        # NOTE: the new session is NOT put in self.sessions yet. Messages that are
        # still arriving under the OLD keys (during a rekey) keep decrypting fine.
        self.pending[peer] = (session, future)

        fields = session.init_fields()   # {"pub": X25519 key, "kem_pub": ML-KEM key (PQ mode)}
        signature = self.identity.sign(init_transcript(self.username, peer, fields))
        await send_frame(self.writer, make_envelope(
            "KEY_INIT", self.username, to=peer,
            insecure=self.insecure,
            id_pub=b64encode(self.identity.public_bytes),
            sig=b64encode(signature),
            **{name: b64encode(value) for name, value in fields.items()}))

        try:
            result = await asyncio.wait_for(asyncio.shield(future), timeout=HANDSHAKE_TIMEOUT)
        except HandshakeRefused as error:
            raise ConnectionError(str(error))
        except asyncio.TimeoutError:
            self.security.event("HANDSHAKE_TIMEOUT", user=self.username,
                                detail=f"no KEY_RESP from {peer}")
            raise ConnectionError(f"HANDSHAKE_TIMEOUT: {peer} did not answer "
                                  f"(offline, or they refused our identity key)")
        finally:
            self.pending.pop(peer, None)

        if result == "ours":
            self.sessions[peer] = session  # swap in the new keys only now
        # result == "theirs": both sides started at once and THEIR handshake won;
        # the session was already stored by the KEY_INIT handler.

        self.on_info(f"Encrypted session with {peer} ready. {self.describe_trust(peer)}")

    # ==================================================================
    # Sending
    # ==================================================================
    async def send_chat(self, peer: str, text: str) -> None:
        """Encrypt `text` for `peer` and send it through the relay."""
        await self.send_encrypted(peer, text, CHAT, "CHAT")

    async def send_file(self, peer: str, path: str) -> str:
        """Send a file in encrypted 32 KB chunks. Returns the file name."""
        info, pieces = prepare_outgoing(path)
        self.on_info(f"Sending {info['name']} ({info['size']:,} bytes, {info['chunks']} chunks) "
                     f"to {peer}, SHA-256 {info['sha256'][:16]}...")
        for piece in pieces:
            await self.send_encrypted(peer, piece, FILE_CHUNK, "FILE_CHUNK")
        self.on_info(f"Sent {info['name']} to {peer}")
        return info["name"]

    async def send_encrypted(self, peer, data, msg_type, envelope_type) -> None:
        """Encrypt one message (text or bytes) and send it."""
        # If a handshake (e.g. a rekey) is running, wait so we use the NEW keys.
        if peer in self.pending:
            await self.pending[peer][1]

        session = self.sessions.get(peer)
        if session is None or not session.ready:
            raise SessionError(f"No encrypted session with {peer}. Use /chat {peer} first.")

        # Step 13: automatic rekey after too many messages or too much time.
        if session.needs_rekey():
            self.on_info(f"Rekeying session with {peer} (limit reached)")
            await self.start_chat(peer)
            session = self.sessions[peer]

        packet = session.encrypt_message(data, msg_type)
        await send_frame(self.writer, make_envelope(
            envelope_type, self.username, to=peer, packet=b64encode(packet)))

    async def ask_who(self):
        await send_frame(self.writer, make_envelope("WHO", self.username))

    # ==================================================================
    # Trust helpers (used by /trust and /safety)
    # ==================================================================
    def safety_number(self, peer: str):
        session = self.sessions.get(peer)
        if session is None or session.peer_identity is None:
            return None
        return crypto_utils.safety_number(self.identity.public_bytes, session.peer_identity)

    def describe_trust(self, peer: str) -> str:
        if self.insecure:
            return "!! INSECURE MODE: identity NOT verified !!"
        session = self.sessions.get(peer)
        suite = f" | {session.suite} + Double Ratchet" if session and session.suite else ""
        number = self.safety_number(peer)
        return f"Safety number: {number}{suite}" if number else ""

    def trust_new_key(self, peer: str) -> bool:
        """Accept a peer's CHANGED identity key (after checking the safety number)."""
        new_key = self.untrusted_keys.pop(peer, None)
        if new_key is None:
            return False
        self.known_peers.trust(peer, new_key)
        return True

    def check_identity(self, peer: str, id_pub: bytes) -> None:
        """Trust on first use. Raises HandshakeRefused if the key CHANGED."""
        result = self.known_peers.check(peer, id_pub)
        if result == "new":
            self.on_info(f"First contact with {peer}: their identity key has been saved. "
                         f"Compare the safety number with {peer} in person to be sure.")
        elif result == "changed":
            self.untrusted_keys[peer] = id_pub
            self.security.event("IDENTITY_CHANGED", user=self.username,
                                detail=f"identity key of {peer} differs from the saved one")
            raise HandshakeRefused(
                f"WARNING: {peer}'s identity key has CHANGED. This could be an attacker. "
                f"Session refused. If {peer} really got a new key, check the safety number "
                f"with them and run /trust {peer}")

    def check_fresh(self, peer, init_fields) -> None:
        """
        A signed KEY_INIT stays validly signed forever, so a malicious relay could
        REPLAY an old one to knock out a working session. Refuse it if it is old,
        or if we have already seen that exact ephemeral key.
        """
        ts_bytes = init_fields.get("ts", b"")
        sent_at = struct.unpack(">Q", ts_bytes)[0] if len(ts_bytes) == 8 else 0
        if abs(time.time() - sent_at) > MAX_CLOCK_SKEW:
            self.security.event("REPLAY_OR_REORDER", user=self.username,
                                detail=f"stale KEY_INIT claiming to be from {peer}")
            raise HandshakeRefused(f"Refused an old (replayed?) key exchange from {peer}. "
                                   f"If this is real, check both laptops' clocks.")
        if init_fields["pub"] in self.seen_init_keys:
            self.security.event("REPLAY_OR_REORDER", user=self.username,
                                detail=f"replayed KEY_INIT from {peer}")
            raise HandshakeRefused(f"Refused a replayed key exchange from {peer}.")
        self.seen_init_keys.append(init_fields["pub"])

    def verify_or_refuse(self, peer, id_pub, signature, transcript) -> None:
        """Check the signature, then the identity (TOFU). Raises HandshakeRefused."""
        if not crypto_utils.verify_signature(id_pub, signature, transcript):
            self.security.event("SIG_FAIL", user=self.username,
                                detail=f"bad handshake signature claiming to be {peer}")
            raise HandshakeRefused(
                f"SIG_FAIL: the key exchange with {peer} was NOT signed by {peer}. "
                f"Possible man-in-the-middle. Session refused.")
        self.check_identity(peer, id_pub)

    # ==================================================================
    # Receive loop: runs forever in the background
    # ==================================================================
    async def receive_loop(self):
        try:
            while True:
                data = await recv_frame(self.reader)
                try:
                    envelope = parse_envelope(data)
                    await self.handle_envelope(envelope)
                except HandshakeRefused as error:
                    self.on_info(str(error))
                except (EnvelopeError, PacketError, SessionError, InvalidTag,
                        ValueError, KeyError) as error:
                    # One bad message must never crash the client.
                    if isinstance(error, InvalidTag):
                        error = "TAG_FAIL (message was tampered with)"
                    self.on_info(f"Rejected a message: {error}")
                except Exception as error:   # last line of defence: log it, keep receiving
                    self.security.event("MALFORMED_FRAME", user=self.username,
                                        detail=f"{type(error).__name__}: {str(error)[:200]}")
                    self.on_info(f"Rejected a malformed message ({type(error).__name__})")
        except (FrameError, ConnectionError, OSError):
            # OSError also covers ssl.SSLError and "connection reset by peer".
            self.on_info("Disconnected from server")
        except asyncio.CancelledError:
            pass
        finally:
            # Wake up connect() if the server closed the connection during HELLO.
            if not self.welcome.is_set():
                self.connect_error = self.connect_error or "Server closed the connection"
                self.welcome.set()

    async def handle_envelope(self, envelope: dict):
        msg_type = envelope.get("type")
        sender = envelope.get("from")

        if msg_type == "WELCOME":
            self.welcome.set()
            if self.pq_missing:
                self.on_info("Post-quantum mode unavailable: 'cryptography' is older than 47.0 "
                             "(run: pip install -U cryptography). Using classic X25519 only.")
            self.on_info(f"Logged in as {self.username}. Online: {', '.join(envelope.get('online', []))}")

        elif msg_type == "WHO":
            self.on_info(f"Online: {', '.join(envelope.get('online', []))}")

        elif msg_type == "ERROR":
            reason = envelope.get("reason")
            if not self.welcome.is_set():
                # Login / register refused.
                self.connect_error = reason
                self.welcome.set()
                return
            self.on_info(f"Server error: {reason}")
            for _session, future in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError(reason))

        elif msg_type == "KEY_INIT":
            await self.handle_key_init(sender, envelope)

        elif msg_type == "KEY_RESP":
            self.handle_key_resp(sender, envelope)

        elif msg_type in ("CHAT", "FILE_CHUNK"):
            self.handle_encrypted(sender, envelope)

        else:
            self.on_info(f"Ignoring unknown message type {msg_type}")

    # ------------------------------------------------------------------
    @staticmethod
    def read_fields(envelope, names):
        """Pull the binary handshake fields that are present out of an envelope."""
        return {name: b64decode(envelope[name]) for name in names if name in envelope}

    async def handle_key_init(self, sender, envelope):
        """Someone wants a session with us -> we are the RESPONDER."""
        init_fields = self.read_fields(envelope, INIT_FIELDS)
        their_id = b64decode(envelope["id_pub"])
        their_sig = b64decode(envelope["sig"])

        # Both sides must agree on the demo mode, otherwise nothing would decrypt.
        if bool(envelope.get("insecure")) != self.insecure:
            raise HandshakeRefused(
                f"{sender} uses {'--insecure' if envelope.get('insecure') else 'secure'} mode but you "
                f"use {'--insecure' if self.insecure else 'secure'} mode. Both must match. Session refused.")

        # Both sides started a handshake at the same moment: the alphabetically
        # SMALLER name stays initiator, the other one answers.
        if sender in self.pending and self.username < sender:
            return  # ignore theirs; they will answer ours

        if not self.insecure:
            self.verify_or_refuse(sender, their_id, their_sig,
                                  init_transcript(sender, self.username, init_fields))
            self.check_fresh(sender, init_fields)

        session = Session(sender, is_initiator=False, insecure=self.insecure, pq=self.pq)
        session.peer_identity = their_id
        try:
            resp_fields = session.respond(init_fields)   # derives the keys
        except (SessionError, ValueError) as error:
            raise HandshakeRefused(f"Handshake with {sender} failed: {error}")

        signature = self.identity.sign(
            resp_transcript(sender, self.username, init_fields, resp_fields))
        await send_frame(self.writer, make_envelope(
            "KEY_RESP", self.username, to=sender,
            insecure=self.insecure,
            id_pub=b64encode(self.identity.public_bytes),
            sig=b64encode(signature),
            **{name: b64encode(value) for name, value in resp_fields.items()}))

        self.sessions[sender] = session

        # If we had our own handshake waiting, theirs replaces it.
        if sender in self.pending:
            _ours, future = self.pending[sender]
            if not future.done():
                future.set_result("theirs")

        self.on_info(f"{sender} started an encrypted session. {self.describe_trust(sender)}")
        self.on_session(sender)

    def handle_key_resp(self, sender, envelope):
        """The answer to OUR KEY_INIT."""
        if sender not in self.pending:
            raise SessionError(f"Unexpected KEY_RESP from {sender}")
        session, future = self.pending[sender]

        resp_fields = self.read_fields(envelope, RESP_FIELDS)
        their_id = b64decode(envelope["id_pub"])
        their_sig = b64decode(envelope["sig"])

        try:
            if not self.insecure:
                self.verify_or_refuse(sender, their_id, their_sig,
                                      resp_transcript(self.username, sender,
                                                      session._init_fields, resp_fields))
            session.peer_identity = their_id
            session.finish(resp_fields)                  # derives the keys
        except (HandshakeRefused, SessionError, ValueError) as error:
            if not future.done():
                future.set_exception(error if isinstance(error, HandshakeRefused)
                                     else HandshakeRefused(f"Handshake with {sender} failed: {error}"))
            return

        # Use the new keys IMMEDIATELY: the peer's first message may already be the
        # very next frame in our receive loop, before start_chat() wakes up.
        self.sessions[sender] = session
        if not future.done():
            future.set_result("ours")

    def handle_encrypted(self, sender, envelope):
        """Decrypt a CHAT or FILE_CHUNK packet (same security checks for both)."""
        session = self.sessions.get(sender)
        if session is None or not session.ready:
            raise SessionError(f"{envelope.get('type')} from {sender} but no session exists")

        try:
            msg_type, plaintext = session.decrypt_packet(b64decode(envelope["packet"]))
        except InvalidTag:
            session.tag_failures += 1
            self.security.event("TAG_FAIL", user=self.username, session_id=session.fingerprint(),
                                detail=f"tampered packet from {sender} "
                                       f"({session.tag_failures}/{Session.MAX_TAG_FAILURES})")
            if session.tag_failures >= Session.MAX_TAG_FAILURES:
                del self.sessions[sender]
                self.incoming_files.cancel_from(sender)
                self.security.event("SESSION_CLOSED_TAG_FAILS", user=self.username,
                                    session_id=session.fingerprint(),
                                    detail=f"session with {sender} closed")
                self.on_info(f"Session with {sender} CLOSED after "
                             f"{Session.MAX_TAG_FAILURES} tampered messages. Use /chat {sender} again.")
            raise
        except SessionError as error:
            self.security.event("REPLAY_OR_REORDER", user=self.username,
                                session_id=session.fingerprint(),
                                detail=f"from {sender}: {error}")
            raise

        if msg_type == FILE_CHUNK:
            self.handle_file_piece(sender, plaintext)
        else:
            text = plaintext.decode("utf-8", errors="replace")
            self.on_message(sender, text)

    def handle_file_piece(self, sender, plaintext):
        try:
            result = self.incoming_files.handle(sender, plaintext)
        except Exception as error:   # malformed or hostile file data must never kill the client
            result = ("failed", f"file from {sender}: {error}")
        if result is None:
            return
        kind, text = result
        if kind == "done":
            self.on_info(f"Received file from {sender}: {text}  (SHA-256 verified)")
        elif kind == "failed":
            self.security.event("FILE_TRANSFER_FAIL", user=self.username, detail=text)
            self.on_info(f"File transfer problem: {text}")
        else:
            self.on_info(text)
