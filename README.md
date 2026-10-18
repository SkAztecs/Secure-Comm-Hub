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
| Post-quantum | **X25519 + ML-KEM-768 hybrid** (like Signal PQXDH / Chrome) | 3 |
| Per-message keys | **Double Ratchet**: a new key for every message, old keys deleted | 3 |
| File transfer | `/send`: 32 KB encrypted chunks + SHA-256 check | 3 |
| Trust | Trust-on-first-use + **safety numbers** users compare | 2 |
| Key derivation | HKDF-SHA256 → ratchet root key | 1 → 3 |
| Encryption | AES-256-GCM, header authenticated as AAD | 1 |
| Replay protection | ratchet message numbers (used keys are deleted) | 1 → 3 |
| Rekeying | ratchet step on every change of direction + full handshake after 1,000 messages / 1 hour | 2 + 3 |
| Tamper response | session closed after 3 failed GCM tags | 2 |
| Security log | JSON Lines events for Pillar 2 (AI Guard) | 2 |
| Firewall hook | blacklist check before TLS, for Pillar 3 | 2 |

Requires **Python 3.11+** and `cryptography` **47+** for post-quantum mode. With an older
version, clients fall back to classic X25519 and print a warning.

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
│   ├── ratchet.py         # the Double Ratchet
│   ├── tls.py             # TLS 1.3 contexts
│   └── security_log.py    # JSONL security events (contract with Pillar 2)
├── server/
│   ├── relay_server.py    # firewall check -> TLS -> login -> route (never decrypts)
│   ├── auth.py            # SQLite users, Argon2id, rate limiter
│   └── firewall_hook.py   # reads Pillar 3's blacklist
├── client/
│   ├── identity.py        # encrypted identity key + known_peers (TOFU)
│   ├── session.py         # handshake (X25519 + ML-KEM) + ratchet per peer
│   ├── file_transfer.py   # chunking, SHA-256 check, safe file names
│   ├── client_core.py     # networking + crypto, no UI
│   ├── cli_client.py      # terminal client
│   └── gui_client.py      # Tkinter client
├── attacks/               # MITM, replay and tamper proxies for the demo
├── demos/ratchet_demo.py  # shows per-message keys and a one-key leak
├── benchmarks/            # bench_crypto.py -> tables + charts for the report
├── Dockerfile, docker-compose.yml
├── scripts/make_certs.py  # creates the private CA + server certificate
├── tests/                 # 75 pytest tests
└── docs/
    ├── setup_guide.md     # START HERE: complete setup, from install to every feature
    ├── protocol_spec.md
    ├── attack_demo.md     # step-by-step Phase 2 demo runbook
    ├── threat_model.md    # STRIDE analysis
    └── wireshark_guide.md
```

Created at runtime (all in `.gitignore`, never commit them): `certs/`, `keys/`, `data/`, `logs/`,
`downloads/`, `benchmarks/results/`.

---

## Setup

> **Full step-by-step guide (install, server, users, demos, attacks, benchmarks, Docker,
> troubleshooting): [`docs/setup_guide.md`](docs/setup_guide.md).** The short version follows.

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
| `/send bob C:\path\file.pdf` | send a file end-to-end encrypted (bob gets it in `downloads\bob\`) |
| `/who` | list online users |
| `/quit` | exit |
| anything else | sent, encrypted, to the active chat only |

The prompt always shows who gets your next message, e.g. `[to bob]>`.

`/sessions` and the session messages show the suite in use, e.g.
`X25519 + ML-KEM-768 (post-quantum hybrid) + Double Ratchet`. `--no-pq` forces classic X25519.

GUI: the **Send file...** button sends a file to the open conversation.

## Phase 3 extras

| Command | What it shows |
|---|---|
| `python -m demos.ratchet_demo` | handshake sizes, a new key per message, and that leaking one key exposes exactly one message |
| `python -m benchmarks.bench_crypto` | handshake / per-message / round-trip / file-throughput numbers → `benchmarks/results/` (`results.md` + 3 PNG charts). Run it on **your** laptop for the report |
| `docker compose up -d relay` then `docker compose run --rm alice --register` | the whole system in containers (see `docker-compose.yml`) |

## Demo flags (attack demonstration only)

| Flag | Effect |
|---|---|
| `--no-tls` (server + clients) | plain TCP, so a proxy or Wireshark can read envelopes and passwords |
| `--insecure` (both clients) | no signatures, no identity check, no replay check, no ratchet / post-quantum, AES-CTR without integrity. Secure and insecure clients refuse each other |

See **`docs/attack_demo.md`** for the full runbook (MITM, replay, bit-flip, brute force).

## Security logs

| File | Written by | Events |
|---|---|---|
| `logs/security.jsonl` | server | LOGIN_OK, REGISTER_OK, LOGIN_FAIL, LOGIN_LOCKOUT, FRAME_TOO_LARGE, MALFORMED_FRAME, HANDSHAKE_TIMEOUT, TLS_FAIL, BLOCKED_CONNECTION |
| `logs/security-<user>.jsonl` | each client | SIG_FAIL, IDENTITY_CHANGED, TAG_FAIL, REPLAY_OR_REORDER, SESSION_CLOSED_TAG_FAILS, HANDSHAKE_TIMEOUT, FILE_TRANSFER_FAIL |

Pillar 3 hook: put one IP per line in `data/blacklist.txt`. New connections from those
IPs are dropped before TLS and logged as `BLOCKED_CONNECTION`.

## Tests

```bash
pytest -v
```
75 tests, covering:
- Phase 1 behaviour: framing, crypto, packets, replay, routing between 3 users.
- Accounts: identity key at rest, Argon2id hashing, generic login errors, brute-force lockout over the network.
- Transport and identity: TLS 1.3, signature checks, trust-on-first-use refusal and `/trust`.
- Session limits: automatic rekey, session closed after 3 tag failures, firewall blacklist.
- Attacks: every attack run against both insecure and secure clients (the MITM proxy also copies the ML-KEM + ratchet handshake).
- Phase 3 crypto: hybrid vs classic handshake, downgrade refusal, out-of-order and late messages, replay, all-or-nothing decrypt, forward secrecy.
- Files: intact delivery (the server never sees the name), SHA-256 failure, path traversal, size limit, no overwrite.
- Code-review fixes: one regression test per finding (transfer-id traversal, malformed messages, message right behind KEY_RESP, replayed KEY_INIT, transfer flood, bad ML-KEM ciphertext).

> **Clocks:** a key exchange older than 5 minutes is refused as a possible replay. If
> two laptops' clocks are far apart, `/chat` fails with "Refused an old (replayed?) key exchange".
> Turn on automatic time sync.

## Security rules for this repo
- Only audited primitives (`cryptography`, `argon2-cffi`). No hand-written crypto.
- A GCM nonce is never reused: it comes from a sequence number that only goes up,
  each direction has its own key, and keys change on rekey.
- Never log keys, passwords or message text.
- `certs/`, `keys/`, `data/`, `logs/` and `.env` are in `.gitignore`.
- `--insecure` and `--no-tls` exist only for the demo and print warnings.
