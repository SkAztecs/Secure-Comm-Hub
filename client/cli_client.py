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
    /send bob <path>  send a file, end-to-end encrypted (saved in downloads/bob/ on his side)
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
            insecure=args.insecure, pq=not getattr(args, "no_pq", False),
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

    HELP = ("Commands: /chat <user>, /switch <user>, /sessions, /safety [user], /trust <user>, "
            "/send <user> <file>, @<user> <msg>, /who, /help, /quit")

    async def handle_line(self, line: str) -> bool:
        """Process one typed line. Returns False when the user wants to quit."""
        # Split "/chat bob" into command "/chat" and argument "bob" (argument may be empty).
        command, _, argument = line.partition(" ")
        argument = argument.strip()
        is_command = line.startswith("/")

        if command == "/quit":
            return False

        if command == "/help":
            self.show_info(self.HELP)

        elif command == "/who":
            await self.client.ask_who()

        elif command == "/sessions":
            ready = [p for p, s in self.client.sessions.items() if s.ready]
            if not ready:
                self.show_info("No sessions yet. Use /chat <user>.")
            for peer in ready:
                mark = "*" if peer == self.active_peer else " "
                print(f"  {mark} {peer}   {self.client.describe_trust(peer)}")

        elif command == "/safety":
            # "/safety" alone = the active chat
            peer = argument or self.active_peer
            if not peer:
                self.show_info("Usage: /safety <user>   (or open a chat first)")
            elif self.client.safety_number(peer):
                self.show_info(f"Safety number with {peer}: {self.client.safety_number(peer)}")
                self.show_info(f"Ask {peer} to run /safety {self.args.name} - the numbers must match.")
            else:
                self.show_info(f"No verified session with {peer}.")

        elif command == "/trust":
            # Deliberately NO default here: trusting a changed key must name the person.
            if not argument:
                self.show_info("Usage: /trust <user>   (only after checking the safety number with them)")
            elif self.client.trust_new_key(argument):
                self.show_info(f"New identity key for {argument} saved. Run /chat {argument} again.")
            else:
                self.show_info(f"No changed key pending for {argument}.")

        elif command == "/send":
            peer, _, path = argument.partition(" ")
            path = path.strip().strip('"').strip("'")
            if not peer or not path:
                self.show_info("Usage: /send <user> <path to file>   e.g. /send bob C:\\Users\\me\\notes.pdf")
            else:
                if peer not in self.client.sessions:
                    await self.client.start_chat(peer)
                await self.client.send_file(peer, path)

        elif command == "/chat":
            if not argument:
                self.show_info("Usage: /chat <user>")
            else:
                await self.client.start_chat(argument)
                self.active_peer = argument
                self.show_info(f"Active chat is now {argument}")

        elif command == "/switch":
            session = self.client.sessions.get(argument)
            if not argument:
                self.show_info("Usage: /switch <user>")
            elif session is None or not session.ready:
                self.show_info(f"No session with {argument}. Use /chat {argument} first.")
            else:
                self.active_peer = argument
                self.show_info(f"Active chat is now {argument}")

        elif line.startswith("@"):
            # "@dhinakar hello there" -> peer = dhinakar, text = hello there
            target, _, text = line[1:].partition(" ")
            if not text.strip():
                self.show_info("Usage: @<user> <message>")
            else:
                await self.send_to(target, text.strip())

        elif is_command:
            self.show_info(f"Unknown command {command}. " + self.HELP)

        elif self.active_peer is None:
            self.show_info("No active chat. Use /chat <user> first.")

        else:
            await self.send_to(self.active_peer, line)

        return True

    async def run(self):
        await self.client.connect(self.args.host, self.args.port, self.password,
                                  register=self.args.register, ssl_context=self.ssl_context)
        self.password = None  # don't keep it in memory longer than needed
        print(self.HELP)

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
    parser.add_argument("--no-pq", action="store_true",
                        help="classic X25519 only (no ML-KEM post-quantum hybrid)")
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
