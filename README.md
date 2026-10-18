# Pillar 1: Secure Messaging

End-to-end encrypted chat for the **AI-Defended Secure Communication Hub**.
Clients talk through a relay server that logs users in and routes messages, but
**cannot read them**.

| Layer | What we use | Phase |
|---|---|---|
| Transport | TCP (`asyncio`), 4-byte length-prefixed frames | 1 |
| Transport security | **TLS 1.3** client ↔ server, private CA, hostname check | 2 |
| Login | **Argon2id** password hashes, 5 failures/min → 60 s lockout | 2 |
| Identity | **Ed25519** identity key per user, stored encrypted (scrypt + AES-GCM) | 2 |
| Key exchange | X25519 ephemeral keys, **signed** with the identity key → no MITM | 1 + 2 |
| Trust | Trust-on-first-use + **safety numbers** users compare | 2 |
| Key derivation | HKDF-SHA256 → one AES key per direction | 1 |
| Encryption | AES-256-GCM, header authenticated as AAD, nonce = sequence number | 1 |
| Replay protection | strict per-direction sequence numbers | 1 |
| Rekeying | new handshake after 1,000 messages or 1 hour | 2 |
| Tamper response | session closed after 3 failed GCM tags | 2 |
| Security log | JSON Lines events for Pillar 2 (AI Guard) | 2 |
| Firewall hook | blacklist check before TLS, for Pillar 3 | 2 |

Requires **Python 3.11+**.

---

## Folder structure

```
secure-messaging/
├── common/
│   ├── message_types.py   # protocol type codes
│   ├── framing.py         # length-prefixed send/receive over TCP
│   ├── crypto_utils.py    # X25519, HKDF, AES-GCM, Ed25519, safety numbers, scrypt
│   ├── packet.py          # build/parse  ver|type|seq|nonce|ciphertext|tag
│   ├── envelope.py        # JSON routing envelope (what the server can see)
│   ├── handshake.py       # exactly what gets signed in KEY_INIT / KEY_RESP
│   ├── tls.py             # TLS 1.3 contexts
│   └── security_log.py    # JSONL security events (contract with Pillar 2)
├── server/
│   ├── relay_server.py    # firewall check -> TLS -> login -> route (never decrypts)
│   ├── auth.py            # SQLite users, Argon2id, rate limiter
│   └── firewall_hook.py   # reads Pillar 3's blacklist
├── client/
│   ├── identity.py        # encrypted identity key + known_peers (TOFU)
│   ├── session.py         # per-peer keys, seq counters, rekey limits
│   ├── client_core.py     # networking + crypto, no UI
│   ├── cli_client.py      # terminal client
│   └── gui_client.py      # Tkinter client
├── attacks/               # MITM, replay and tamper proxies for the demo
├── scripts/make_certs.py  # creates the private CA + server certificate
├── tests/                 # 41 pytest tests
└── docs/
    ├── protocol_spec.md
    ├── attack_demo.md     # step-by-step Phase 2 demo runbook
    └── wireshark_guide.md
```

Created at runtime (all in `.gitignore`, never commit them): `certs/`, `keys/`, `data/`, `logs/`.

---

## Setup

```bash
python -m venv venv
# Windows: venv\Scripts\activate      macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

## 1. Create the TLS certificate (once, on the server machine)

```bash
python scripts/make_certs.py --ip 172.17.177.67
```
Use the IP the clients will type in `--host`. Repeat `--ip` for several IPs.
Then copy **`certs/ca.pem` only** to `certs/ca.pem` on every client machine.
The `.key` files never leave the server.

## 2. Start the server

```bash
python -m server.relay_server --host 0.0.0.0 --port 9000
```

## 3. Start clients

First time on a machine (creates your identity key and your account):
```bash
python -m client.cli_client --name alice --host 172.17.177.67 --register
```
After that, drop `--register`. You will be asked for two secrets:

| Prompt | What it is | Where it goes |
|---|---|---|
| Key passphrase | unlocks `keys/<name>/identity.json` | never leaves your machine |
| Account password (8+ chars) | logs you in | sent to the server inside TLS, stored there as an Argon2id hash |

GUI: `python -m client.gui_client --host 172.17.177.67 --port 9000`. The login screen has
the same fields plus a "register" tick box.

> An account is tied to the identity key it registered with. If you log in from a
> different `keys/` folder, the server refuses (`Identity key does not match this account`).

## 4. Chat

| Command | What it does |
|---|---|
| `/chat bob` | start a new signed, encrypted session with bob and make him active |
| `/switch dhinakar` | make an existing session active (no new handshake) |
| `@dhinakar hello` | send one message to dhinakar without switching |
| `/sessions` | list sessions (`*` = active) with their safety numbers |
| `/safety bob` | show the safety number. Bob runs `/safety alice`; the numbers must match |
| `/trust bob` | accept bob's **changed** identity key (only after checking the safety number) |
| `/who` | list online users |
| `/quit` | exit |
| anything else | sent, encrypted, to the active chat only |

The prompt always shows who gets your next message, e.g. `[to bob]>`.

## Demo flags (attack demonstration only)

| Flag | Effect |
|---|---|
| `--no-tls` (server + clients) | plain TCP, so a proxy or Wireshark can read envelopes and passwords |
| `--insecure` (both clients) | no signatures, no identity check, no replay check, AES-CTR without integrity |

See **`docs/attack_demo.md`** for the full runbook (MITM, replay, bit-flip, brute force).

## Security logs

| File | Written by | Events |
|---|---|---|
| `logs/security.jsonl` | server | LOGIN_OK, REGISTER_OK, LOGIN_FAIL, LOGIN_LOCKOUT, FRAME_TOO_LARGE, MALFORMED_FRAME, HANDSHAKE_TIMEOUT, TLS_FAIL, BLOCKED_CONNECTION |
| `logs/security-<user>.jsonl` | each client | SIG_FAIL, IDENTITY_CHANGED, TAG_FAIL, REPLAY_OR_REORDER, SESSION_CLOSED_TAG_FAILS, HANDSHAKE_TIMEOUT |

Pillar 3 hook: put one IP per line in `data/blacklist.txt`. New connections from those
IPs are dropped before TLS and logged as `BLOCKED_CONNECTION`.

## Tests

```bash
pytest -v
```
41 tests, covering:
- Phase 1 behaviour: framing, crypto, packets, replay, routing between 3 users.
- Accounts: identity key at rest, Argon2id hashing, generic login errors, brute-force lockout over the network.
- Transport and identity: TLS 1.3, signature checks, trust-on-first-use refusal and `/trust`.
- Session limits: automatic rekey, session closed after 3 tag failures, firewall blacklist.
- Attacks: every attack run against both insecure and secure clients.

## Security rules for this repo
- Only audited primitives (`cryptography`, `argon2-cffi`). No hand-written crypto.
- A GCM nonce is never reused: it comes from a sequence number that only goes up,
  each direction has its own key, and keys change on rekey.
- Never log keys, passwords or message text.
- `certs/`, `keys/`, `data/`, `logs/` and `.env` are in `.gitignore`.
- `--insecure` and `--no-tls` exist only for the demo and print warnings.
