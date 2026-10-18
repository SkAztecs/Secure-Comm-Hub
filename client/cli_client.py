"""
cli_client.py
-------------
Terminal chat client.

Run:
    python -m client.cli_client --name alice --host 127.0.0.1 --port 9000

You can have encrypted sessions with SEVERAL people at once.
Each session has its OWN keys. Exactly one of them is the "active chat":
plain text you type goes ONLY to the active chat, and the prompt always
shows who that is, e.g.   [to bob]>

Commands:
    /chat bob         start a NEW encrypted session with bob and make him active
    /switch dhinakar  make an EXISTING session active (no new handshake)
    /sessions         list your sessions (* = active)
    @dhinakar hi      send ONE message to dhinakar without switching
    /who              list online users
    /quit             exit
    anything else     sent (encrypted) to the active chat only
"""

import argparse
import asyncio
import os
from datetime import datetime

from client.client_core import ChatClient


def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


class CliChat:
    def __init__(self, args):
        self.args = args
        self.active_peer = None
        self.client = ChatClient(args.name, on_message=self.show_message,
                                 on_info=self.show_info, on_session=self.new_session)

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
            # Our active partner re-did the handshake (e.g. they reconnected).
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
                print(f"  {mark} {peer}  (fingerprint {self.client.sessions[peer].fingerprint()})")

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
            self.show_info("Unknown command. Try /chat, /switch, /sessions, /who, /quit")

        elif self.active_peer is None:
            self.show_info("No active chat. Use /chat <user> first.")

        else:
            await self.send_to(self.active_peer, line)

        return True

    async def run(self):
        await self.client.connect(self.args.host, self.args.port)
        print("Commands: /chat <user>, /switch <user>, /sessions, @<user> <msg>, /who, /quit")

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


def main():
    parser = argparse.ArgumentParser(description="Pillar 1 secure chat - terminal client")
    parser.add_argument("--name", required=True, help="your username")
    parser.add_argument("--host", default=os.getenv("RELAY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("RELAY_PORT", "9000")))
    args = parser.parse_args()

    try:
        asyncio.run(CliChat(args).run())
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
