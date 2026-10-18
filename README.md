# Pillar 1 — Secure Messaging

End-to-end encrypted chat for the **AI-Defended Secure Communication Hub**.
Two clients talk through a relay server that routes messages but **cannot read them**.

| Layer | What we use |
|---|---|
| Transport | TCP (`asyncio`), 4-byte length-prefixed frames |
| Key exchange | X25519 (ephemeral, new keys every session → forward secrecy) |
| Key derivation | HKDF-SHA256 → one AES key per direction |
| Encryption | AES-256-GCM, header authenticated as AAD, nonce = sequence number |
| Replay protection | strict per-direction sequence numbers |

> **Phase 1 status:** baseline secure chat. The key exchange is **not yet authenticated**
> (Ed25519 signatures + safety numbers come in Phase 2), so a man-in-the-middle is
> still possible. That gap is intentional and becomes part of the Phase 2 attack demo.

---

## Folder structure

```
secure-messaging/
├── common/
│   ├── message_types.py   # protocol type codes (HELLO, KEY_INIT, CHAT ...)
│   ├── framing.py         # length-prefixed send/receive over TCP
│   ├── crypto_utils.py    # X25519, HKDF, AES-256-GCM wrappers
│   ├── packet.py          # build/parse  ver|type|seq|nonce|ciphertext|tag
│   └── envelope.py        # JSON routing envelope (what the server can see)
├── server/
│   └── relay_server.py    # routes envelopes, never decrypts
├── client/
│   ├── session.py         # per-peer keys, handshake, seq counters
│   ├── client_core.py     # networking + crypto, no UI
│   ├── cli_client.py      # terminal client
│   └── gui_client.py      # Tkinter client
├── tests/                 # pytest: unit + full server/client integration
├── docs/
│   ├── protocol_spec.md
│   └── wireshark_guide.md # how to capture the "only ciphertext" proof
├── attacks/  benchmarks/  # Phase 2 / Phase 3
├── requirements.txt
└── config.example.env
```

---

## Setup

```bash
python -m venv venv
# Windows: venv\Scripts\activate      macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

Tkinter ships with Python on Windows and macOS. On Ubuntu: `sudo apt install python3-tk`.

## Run (all commands from the `secure-messaging/` folder)

**1. Start the relay server**
```bash
python -m server.relay_server --host 0.0.0.0 --port 9000
```

**2. Start two clients** (two terminals, or two different laptops on the same Wi-Fi —
replace `127.0.0.1` with the server laptop's IP from `ipconfig` / `ifconfig`)

Terminal client:
```bash
python -m client.cli_client --name alice --host 127.0.0.1 --port 9000
python -m client.cli_client --name bob   --host 127.0.0.1 --port 9000
```

GUI client:
```bash
python -m client.gui_client --host 127.0.0.1 --port 9000
```

**3. Chat**

You can hold encrypted sessions with several people at once. Each session has its own
keys, and exactly one is your **active chat**.

Terminal client — the prompt always shows who gets your next message, e.g. `[to bob]>`

| Command | What it does |
|---|---|
| `/chat bob` | start a new encrypted session with bob and make him active |
| `/switch dhinakar` | make an existing session active (no new handshake) |
| `@dhinakar hello` | send one message to dhinakar without switching |
| `/sessions` | list your sessions (`*` = active) |
| `/who` | list online users |
| `/quit` | exit |
| anything else | sent, encrypted, to the active chat only |

Messages from someone who is not your active chat are marked `(not active)`.

GUI client — every person gets their own conversation in the left list, unread
messages show as `(n)`, and the button always reads **Send to <name>**.

## Tests

```bash
pytest -v
```
19 tests: framing, key derivation, AES-GCM tamper detection, packet parsing,
replay rejection, a full server + 2 clients run that checks the server
never sees the plaintext, and a 3-user run that checks each message reaches
only the person it was sent to.

## Security rules for this repo
- Only audited primitives from the `cryptography` library — no hand-written crypto.
- A GCM nonce is never reused: it is built from a sequence number that only goes up,
  and each direction has its own key.
- Never log keys, passwords or message text.
- Keys, `.env`, databases and logs are in `.gitignore`.
