"""
cli_client.py
-------------
Terminal chat client.

First time (creates your identity key + account):
    python -m client.cli_client --name alice --host 172.17.177.67 --register
After that:
    python -m client.cli_client --name alice --host 172.17.177.67

You will be asked for:
    - your ACCOUNT password   (sent to the server inside TLS, stored there as an Argon2id hash)
    - your KEY passphrase     (never leaves your machine; unlocks keys/<name>/identity.json)

TLS is ON by default and needs certs/ca.pem (made by scripts/make_certs.py on the server).

Demo-only flags:
    --no-tls     plain TCP (to show what a network sniffer / MITM proxy can see)
    --insecure   skip signatures, identity checks and replay checks; use AES-CTR with no
                 integrity. BOTH chat partners must use it. Never for real use.

Commands:
    /chat bob         start a NEW encrypted session with bob and make him active
    /switch dhinakar  make an EXISTING session active (no new handshake)
    /sessions         list your sessions (* = active)
    /safety bob       show the safety number for bob (compare it with bob in person)
    /trust bob        accept bob's CHANGED identity key (only after checking the number!)
    @dhinakar hi      send ONE message to dhinakar without switching
    /who              list online users
    /quit             exit
    anything else     sent (encrypted) to the active chat only
"""

import argparse
import asyncio
import getpass
import os
from datetime import datetime

from client.client_core import ChatClient
from client.identity import Identity, IdentityError, KnownPeers
from common import tls
from common.security_log import SecurityLogger


def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


INSECURE_BANNER = """
############################################################
#  INSECURE DEMO MODE: no signatures, no identity checks,  #
#  no replay protection, NO message integrity (AES-CTR).   #
#  For the attack demonstration ONLY.                      #
############################################################"""


class CliChat:
    def __init__(self, args, identity, password, ssl_context):
        self.args = args
        self.password = password
        self.ssl_context = ssl_context
        self.active_peer = None
        self.client = ChatClient(
            args.name, identity, KnownPeers(args.name, args.keys_dir),
            insecure=args.insecure,
            on_message=self.show_message, on_info=self.show_info, on_session=self.new_session,
            security_log=SecurityLogger(os.path.join(args.log_dir, f"security-{args.name}.jsonl")))

    # ------------------------------------------------------------------
    # Output helpers (called from the network side)
    # ------------------------------------------------------------------
    def prompt(self) -> str:
        """The input prompt always says where your next message will go."""
        return f"[to {self.active_peer}]> " if self.active_peer else "[no active chat]> "

    def show_message(self, peer, text):
        # Mark messages from someone who is NOT the active chat, so it is obvious
        # that typing a plain reply would go to someone else.
        if peer == self.active_peer:
            print(f"\r[{timestamp()}] {peer}: {text}")
        else:
            print(f"\r[{timestamp()}] {peer} (not active): {text}"
                  f"   -> reply with  @{peer} <msg>  or  /switch {peer}")

    def show_info(self, text):
        print(f"\r[{timestamp()}] * {text}")

    def new_session(self, peer):
        """Someone else started a session with us."""
        if self.active_peer is None:
            # Nothing active yet -> this new session becomes active.
            self.active_peer = peer
            print(f"\r[{timestamp()}] * Active chat is now {peer}")
        elif peer == self.active_peer:
            # Our active partner re-did the handshake (rekey or reconnect).
            print(f"\r[{timestamp()}] * {peer} renewed the session keys")
        else:
            # Do NOT silently switch: tell the user how to reach the new person.
            print(f"\r[{timestamp()}] * Active chat is still {self.active_peer}. "
                  f"Use  /switch {peer}  or  @{peer} <msg>  to talk to {peer}.")

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------
    async def read_line(self) -> str:
        """input() blocks, so run it in a background thread (keeps asyncio alive)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, input, self.prompt())

    async def send_to(self, peer: str, text: str):
        """Send one encrypted message and echo it with the receiver's name."""
        await self.client.send_chat(peer, text)
        print(f"[{timestamp()}] me -> {peer}: {text}")

    async def handle_line(self, line: str) -> bool:
        """Process one typed line. Returns False when the user wants to quit."""
        if line == "/quit":
            return False

        if line == "/who":
            await self.client.ask_who()

        elif line == "/sessions":
            ready = [p for p, s in self.client.sessions.items() if s.ready]
            if not ready:
                self.show_info("No sessions yet. Use /chat <user>.")
            for peer in ready:
                mark = "*" if peer == self.active_peer else " "
                print(f"  {mark} {peer}   {self.client.describe_trust(peer)}")

        elif line.startswith("/safety "):
            peer = line.split(maxsplit=1)[1].strip()
            number = self.client.safety_number(peer)
            if number:
                self.show_info(f"Safety number with {peer}: {number}")
                self.show_info(f"Ask {peer} to run /safety {self.args.name} - the numbers must match.")
            else:
                self.show_info(f"No verified session with {peer}.")

        elif line.startswith("/trust "):
            peer = line.split(maxsplit=1)[1].strip()
            if self.client.trust_new_key(peer):
                self.show_info(f"New identity key for {peer} saved. Run /chat {peer} again.")
            else:
                self.show_info(f"No changed key pending for {peer}.")

        elif line.startswith("/chat "):
            peer = line.split(maxsplit=1)[1].strip()
            await self.client.start_chat(peer)
            self.active_peer = peer
            self.show_info(f"Active chat is now {peer}")

        elif line.startswith("/switch "):
            peer = line.split(maxsplit=1)[1].strip()
            session = self.client.sessions.get(peer)
            if session is None or not session.ready:
                self.show_info(f"No session with {peer}. Use /chat {peer} first.")
            else:
                self.active_peer = peer
                self.show_info(f"Active chat is now {peer}")

        elif line.startswith("@"):
            # "@dhinakar hello there" -> peer = dhinakar, text = hello there
            target, _, text = line[1:].partition(" ")
            if not text.strip():
                self.show_info("Usage: @<user> <message>")
            else:
                await self.send_to(target, text.strip())

        elif line.startswith("/"):
            self.show_info("Unknown command. Try /chat, /switch, /sessions, /safety, /trust, /who, /quit")

        elif self.active_peer is None:
            self.show_info("No active chat. Use /chat <user> first.")

        else:
            await self.send_to(self.active_peer, line)

        return True

    async def run(self):
        await self.client.connect(self.args.host, self.args.port, self.password,
                                  register=self.args.register, ssl_context=self.ssl_context)
        self.password = None  # don't keep it in memory longer than needed
        print("Commands: /chat <user>, /switch <user>, /sessions, /safety <user>, "
              "/trust <user>, @<user> <msg>, /who, /quit")

        while True:
            line = (await self.read_line()).strip()
            if not line:
                continue
            try:
                if not await self.handle_line(line):
                    break
            except Exception as error:  # show any error, keep the client running
                self.show_info(f"Error: {error}")

        await self.client.close()


def build_parser():
    parser = argparse.ArgumentParser(description="Pillar 1 secure chat - terminal client")
    parser.add_argument("--name", required=True, help="your username")
    parser.add_argument("--host", default=os.getenv("RELAY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("RELAY_PORT", "9000")))
    parser.add_argument("--register", action="store_true", help="create a new account")
    parser.add_argument("--ca", default="certs/ca.pem", help="CA certificate for TLS")
    parser.add_argument("--keys-dir", default="keys", help="where identity keys are stored")
    parser.add_argument("--log-dir", default="logs", help="where security logs are written")
    parser.add_argument("--no-tls", action="store_true", help="DEMO ONLY: plain TCP")
    parser.add_argument("--insecure", action="store_true", help="DEMO ONLY: disable Phase 2 checks")
    # For scripted demos/tests only - typing secrets on the command line leaves them
    # in your shell history, so normally leave these out and get prompted.
    parser.add_argument("--password", help=argparse.SUPPRESS)
    parser.add_argument("--passphrase", help=argparse.SUPPRESS)
    return parser


def main():
    args = build_parser().parse_args()

    if args.insecure:
        print(INSECURE_BANNER)
    if args.no_tls:
        print("!! TLS disabled: your password and usernames are visible on the network !!")
        ssl_context = None
    else:
        if not os.path.exists(args.ca):
            raise SystemExit(f"CA certificate {args.ca} not found. Copy ca.pem from the server "
                             f"into certs/ (or use --no-tls for the demo).")
        ssl_context = tls.client_context(args.ca)

    # 1. Unlock (or create) the identity key - this never leaves the machine.
    if Identity.exists(args.name, args.keys_dir):
        passphrase = args.passphrase or getpass.getpass("Key passphrase (unlocks your identity key): ")
    elif not args.register:
        # No key AND not registering -> almost certainly a typo or a forgotten --register.
        # Don't silently create a key with a passphrase the user didn't mean to set.
        raise SystemExit(f"No identity key for '{args.name}' on this machine "
                         f"(looked in {args.keys_dir}/{args.name}/).\n"
                         f"First time? Add --register to create your key and account.")
    else:
        print(f"Creating a NEW identity key for '{args.name}'. Choose a key passphrase "
              f"(you will need it every time you log in on this machine).")
        passphrase = args.passphrase
        while passphrase is None:
            first = getpass.getpass("New key passphrase: ")
            second = getpass.getpass("Repeat key passphrase: ")
            if not first:
                print("Passphrase can't be empty.")
            elif first != second:
                print("The two passphrases don't match - try again.")
            else:
                passphrase = first
    try:
        identity = Identity.load_or_create(args.name, passphrase, args.keys_dir)
    except IdentityError as error:
        raise SystemExit(str(error))

    # 2. Account password - sent to the server inside TLS.
    password = args.password or getpass.getpass("Account password: ")

    try:
        asyncio.run(CliChat(args, identity, password, ssl_context).run())
    except ConnectionError as error:
        print(f"Could not log in: {error}")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
