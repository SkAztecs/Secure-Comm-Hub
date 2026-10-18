"""
gui_client.py
-------------
Tkinter chat window on top of ChatClient.

Layout:
    +-------------------+------------------------------------------+
    | Conversations     |  Encrypted session with bob (AES-GCM)    |
    |   bob             |  [12:00] bob: hi                         |
    | > dhinakar (2)    |  [12:01] me -> bob: hello                |
    |                   |                                          |
    | [new chat: ____]  |  [ message box               ] [Send to bob]
    +-------------------+------------------------------------------+

Every person you talk to has their OWN session (own keys) and their OWN
history. You only see one conversation at a time, the "Send" button always
names who will receive the message, and unread messages from other people
show as a count next to their name. So a reply can never go to the wrong person
without you seeing it.

Threading:
    - Tkinter runs in the MAIN thread (it must).
    - asyncio (network + crypto) runs in a BACKGROUND thread.
    - GUI -> network : asyncio.run_coroutine_threadsafe(...)
    - network -> GUI : events go into a queue.Queue; the GUI checks it every 100 ms.

Run:
    python -m client.gui_client --host 127.0.0.1 --port 9000
"""

import argparse
import asyncio
import os
import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext

from client.client_core import ChatClient


def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


class ChatWindow:
    def __init__(self, root, host, port):
        self.root = root
        self.host = host
        self.port = port
        self.client = None

        self.active_peer = None
        self.histories = {}   # peer -> list of text lines (one conversation each)
        self.unread = {}      # peer -> number of unread messages
        self.peer_order = []  # peers in the order they appear in the list

        # Events coming FROM the network thread TO the GUI.
        self.events = queue.Queue()

        # Start a private asyncio loop in a background thread.
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()

        self.build_login_screen()
        self.root.after(100, self.process_events)

    # ==================================================================
    # Screens
    # ==================================================================
    def build_login_screen(self):
        self.root.title("Secure Chat - login")
        self.login_frame = tk.Frame(self.root, padx=20, pady=20)
        self.login_frame.pack()

        tk.Label(self.login_frame, text="Username").grid(row=0, column=0, sticky="w")
        self.name_entry = tk.Entry(self.login_frame, width=25)
        self.name_entry.grid(row=0, column=1, pady=4)

        tk.Label(self.login_frame, text="Server").grid(row=1, column=0, sticky="w")
        self.server_entry = tk.Entry(self.login_frame, width=25)
        self.server_entry.insert(0, f"{self.host}:{self.port}")
        self.server_entry.grid(row=1, column=1, pady=4)

        tk.Button(self.login_frame, text="Connect", command=self.on_connect).grid(
            row=2, column=0, columnspan=2, pady=8)
        self.name_entry.bind("<Return>", lambda e: self.on_connect())
        self.name_entry.focus()

    def build_chat_screen(self):
        self.login_frame.destroy()
        self.root.title(f"Secure Chat - {self.client.username}")

        # ---------- left column: conversation list ----------
        left = tk.Frame(self.root, padx=8, pady=8)
        left.pack(side="left", fill="y")

        tk.Label(left, text="Conversations", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.peer_list = tk.Listbox(left, width=22, height=16, exportselection=False)
        self.peer_list.pack(fill="y", expand=True, pady=4)
        self.peer_list.bind("<<ListboxSelect>>", self.on_select_peer)

        tk.Label(left, text="Start new chat with:").pack(anchor="w", pady=(8, 0))
        self.new_peer_entry = tk.Entry(left, width=22)
        self.new_peer_entry.pack()
        self.new_peer_entry.bind("<Return>", lambda e: self.on_start_chat())
        tk.Button(left, text="Start encrypted chat", command=self.on_start_chat).pack(fill="x", pady=4)
        tk.Button(left, text="Who's online", command=self.on_who).pack(fill="x")

        # ---------- right column: the selected conversation ----------
        right = tk.Frame(self.root, padx=8, pady=8)
        right.pack(side="left", fill="both", expand=True)

        # Lock label: says which encrypted session you are looking at.
        self.lock_label = tk.Label(right, text="No conversation selected", fg="gray", anchor="w")
        self.lock_label.pack(fill="x")

        self.history = scrolledtext.ScrolledText(right, width=60, height=18, state="disabled")
        self.history.pack(fill="both", expand=True, pady=4)

        bottom = tk.Frame(right)
        bottom.pack(fill="x")
        self.message_entry = tk.Entry(bottom)
        self.message_entry.pack(side="left", fill="x", expand=True)
        self.message_entry.bind("<Return>", lambda e: self.on_send())
        # The Send button always names the receiver.
        self.send_button = tk.Button(bottom, text="Send", command=self.on_send, state="disabled")
        self.send_button.pack(side="left", padx=4)

        # Status line for system messages (connections, errors).
        self.status_label = tk.Label(right, text="", fg="gray", anchor="w")
        self.status_label.pack(fill="x", pady=(4, 0))

    # ==================================================================
    # Conversation bookkeeping
    # ==================================================================
    def add_peer(self, peer):
        """Make sure `peer` has a history and a row in the list."""
        if peer not in self.histories:
            self.histories[peer] = []
            self.unread[peer] = 0
            self.peer_order.append(peer)
            self.refresh_peer_list()

    def add_line(self, peer, line):
        """Store one line in `peer`'s conversation and show it if it is open."""
        self.add_peer(peer)
        full_line = f"[{timestamp()}] {line}"
        self.histories[peer].append(full_line)

        if peer == self.active_peer:
            self.write_to_history_box(full_line)
        elif not line.startswith("*"):
            # Only real messages count as unread, not "* session started" notes.
            self.unread[peer] += 1
            self.refresh_peer_list()

    def refresh_peer_list(self):
        """Redraw the list: '> ' marks the open chat, (n) = unread count."""
        self.peer_list.delete(0, "end")
        for index, peer in enumerate(self.peer_order):
            marker = "> " if peer == self.active_peer else "   "
            count = f"  ({self.unread[peer]})" if self.unread[peer] else ""
            self.peer_list.insert("end", f"{marker}{peer}{count}")
            if peer == self.active_peer:
                self.peer_list.selection_clear(0, "end")
                self.peer_list.selection_set(index)

    def open_conversation(self, peer):
        """Switch the right-hand side to `peer`'s conversation."""
        self.active_peer = peer
        self.unread[peer] = 0

        # Redraw the history box with only this peer's lines.
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        self.history.configure(state="disabled")
        for line in self.histories[peer]:
            self.write_to_history_box(line)

        session = self.client.sessions.get(peer)
        fingerprint = session.fingerprint() if session else "?"
        self.lock_label.config(
            text=f"\U0001F512 Encrypted session with {peer}  (AES-256-GCM, fingerprint {fingerprint})",
            fg="green")
        self.send_button.config(text=f"Send to {peer}", state="normal")
        self.refresh_peer_list()
        self.message_entry.focus()

    def write_to_history_box(self, line):
        self.history.configure(state="normal")
        self.history.insert("end", line + "\n")
        self.history.configure(state="disabled")
        self.history.see("end")

    def set_status(self, text):
        self.status_label.config(text=f"[{timestamp()}] {text}")

    # ==================================================================
    # Helpers
    # ==================================================================
    def run_async(self, coroutine):
        """Run a coroutine on the background loop; report errors to the GUI."""
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)

        def done(f):
            error = f.exception()
            if error:
                self.events.put(("error", str(error)))
        future.add_done_callback(done)
        return future

    # ==================================================================
    # Button handlers (GUI thread)
    # ==================================================================
    def on_connect(self):
        name = self.name_entry.get().strip()
        host, _, port = self.server_entry.get().strip().partition(":")
        if not name:
            messagebox.showerror("Error", "Enter a username")
            return

        # Callbacks run in the NETWORK thread -> they only put events in the queue.
        self.client = ChatClient(
            name,
            on_message=lambda peer, text: self.events.put(("message", peer, text)),
            on_info=lambda text: self.events.put(("info", text)),
            on_session=lambda peer: self.events.put(("incoming_session", peer)),
        )

        async def connect():
            await self.client.connect(host, int(port or 9000))
            self.events.put(("connected",))

        self.run_async(connect())

    def on_start_chat(self):
        peer = self.new_peer_entry.get().strip()
        if not peer:
            return
        self.new_peer_entry.delete(0, "end")

        async def start():
            await self.client.start_chat(peer)
            self.events.put(("session_ready", peer))

        self.run_async(start())

    def on_select_peer(self, event):
        selection = self.peer_list.curselection()
        if selection:
            self.open_conversation(self.peer_order[selection[0]])

    def on_who(self):
        self.run_async(self.client.ask_who())

    def on_send(self):
        text = self.message_entry.get().strip()
        if not text or self.active_peer is None:
            return
        peer = self.active_peer  # capture NOW, in case the user switches chats
        self.message_entry.delete(0, "end")
        self.add_line(peer, f"me: {text}")
        self.run_async(self.client.send_chat(peer, text))

    # ==================================================================
    # Queue processing (GUI thread, every 100 ms)
    # ==================================================================
    def process_events(self):
        while not self.events.empty():
            event = self.events.get()
            kind = event[0]

            if kind == "connected":
                self.build_chat_screen()
                self.set_status(f"Connected as {self.client.username}")

            elif kind == "error":
                if hasattr(self, "status_label"):
                    self.set_status(f"Error: {event[1]}")
                else:
                    messagebox.showerror("Error", event[1])

            elif not hasattr(self, "status_label"):
                continue  # chat screen not built yet

            elif kind == "info":
                self.set_status(event[1])

            elif kind == "session_ready":
                # WE started this session -> open it straight away.
                peer = event[1]
                self.add_peer(peer)
                self.add_line(peer, "* encrypted session started")
                self.open_conversation(peer)

            elif kind == "incoming_session":
                # SOMEONE ELSE started a session: add them to the list, but do NOT
                # steal focus from the chat the user is currently in.
                peer = event[1]
                self.add_peer(peer)
                self.add_line(peer, f"* {peer} started an encrypted session")
                if self.active_peer is None:
                    self.open_conversation(peer)

            elif kind == "message":
                peer, text = event[1], event[2]
                self.add_line(peer, f"{peer}: {text}")

        self.root.after(100, self.process_events)


def main():
    parser = argparse.ArgumentParser(description="Pillar 1 secure chat - GUI client")
    parser.add_argument("--host", default=os.getenv("RELAY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("RELAY_PORT", "9000")))
    args = parser.parse_args()

    root = tk.Tk()
    ChatWindow(root, args.host, args.port)
    root.mainloop()


if __name__ == "__main__":
    main()
