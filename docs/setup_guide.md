# Pillar 1 Secure Messaging: complete setup guide

From a fresh Windows laptop to every feature: chat, file transfer, attack demo,
benchmarks and Docker. All commands are for **Windows PowerShell**.
On macOS/Linux, replace `venv\Scripts\Activate.ps1` with `source venv/bin/activate`
and `\` with `/` in paths.

**Words used below**
- **Server laptop:** the laptop that runs the relay server. It can also run clients.
- **Client laptop:** any laptop where someone chats (alice, bob, …).
- **`<SERVER-IP>`:** the server laptop's Wi-Fi IPv4 address, e.g. `172.17.177.67`.

---

## Part A: one-time installation (every laptop)

### A1. Requirements

| Need | Check with | Get it from |
|---|---|---|
| Python **3.11 or newer** | `python --version` | python.org, and tick "Add python.exe to PATH" |
| The project folder | `dir G:\CN\secure-messaging` | unzip `secure-messaging-phase3.zip` |
| All laptops on the **same Wi-Fi** | — | — |

### A2. Create the virtual environment (once per laptop)

```powershell
cd G:\CN\secure-messaging
python -m venv venv
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& .\venv\Scripts\Activate.ps1)
pip install -U -r requirements.txt
```

### A3. Check the install

```powershell
python -c "import cryptography; print(cryptography.__version__)"
pytest -q
```

| Check | Expected |
|---|---|
| `cryptography` version | **47 or higher**. Older still works, but without post-quantum mode |
| `pytest -q` | `75 passed` |

### A4. Every new terminal

Every time you open a terminal, run these two lines first:

```powershell
cd G:\CN\secure-messaging
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& .\venv\Scripts\Activate.ps1)
```

You must see **`(venv)`** at the start of the prompt.

---

## Part B: one-time server setup (server laptop only)

### B1. Find the server IP

```powershell
ipconfig
```
Note the **IPv4 Address** under "Wireless LAN adapter Wi-Fi".

### B2. Create the TLS certificate

```powershell
python scripts/make_certs.py --ip <SERVER-IP>
```
Expected output: `Server certificate valid for: localhost, 127.0.0.1, <SERVER-IP>`.

This creates `certs\` with four files:

| File | Secret? | Where it goes |
|---|---|---|
| `ca.pem` | no | copy to **every client laptop** |
| `ca.key` | **yes** | stays on the server laptop |
| `server.pem` | no | stays on the server laptop |
| `server.key` | **yes** | stays on the server laptop |

### B3. Give the CA certificate to the client laptops

On each client laptop, create a `certs` folder inside its `secure-messaging` folder and
copy **only `ca.pem`** into it (USB, WhatsApp or email are fine; it's public).

Do this again whenever you rerun `make_certs.py`, for example after your IP changes.

### B4. Allow the server through Windows Firewall

The first time the server starts, Windows asks whether Python may use the network. Tick
**Private networks** and click **Allow**. If you clicked Cancel, run this once in an
**administrator** PowerShell:

```powershell
New-NetFirewallRule -DisplayName "SecureChat 9000" -Direction Inbound -Protocol TCP -LocalPort 9000 -Action Allow
```

---

## Part C: start the server (every time)

Terminal 1 on the server laptop:

```powershell
python -m server.relay_server --host 0.0.0.0 --port 9000
```

Expected: `Relay server listening on 0.0.0.0:9000  [TLS 1.3]`. Leave this terminal open;
`Ctrl+C` stops the server.

The server creates:

| File | Contents |
|---|---|
| `data\users.db` | accounts (passwords stored as Argon2id hashes, plus each account's identity key) |
| `logs\security.jsonl` | security events for Pillar 2 |
| `data\blacklist.txt` | (you or Pillar 3 create it) IPs to block, one per line |

---

## Part D: users

### D1. Register (first time for each user on each laptop)

```powershell
python -m client.cli_client --name alice --host <SERVER-IP> --port 9000 --register
```

You choose all three secrets:

| Prompt | What it is | Rules |
|---|---|---|
| New key passphrase (asked twice) | unlocks alice's identity key on **this laptop** | never leaves the laptop; can't be recovered if forgotten |
| Account password | server login | 8+ characters |

You'll see `Logged in as alice`. The client creates:
- `keys\alice\identity.json`: the identity key, encrypted with the passphrase
- `keys\alice\known_peers.json`: the contacts alice has verified

### D2. Log in (every other time)

Same command **without** `--register`, typing the same passphrase and password:

```powershell
python -m client.cli_client --name alice --host <SERVER-IP> --port 9000
```

### D3. GUI instead of the terminal

```powershell
python -m client.gui_client --host <SERVER-IP> --port 9000
```
Fill in the username, account password and key passphrase:
- Tick **Create new account (register)** only the first time.
- Leave **Use TLS 1.3** ticked.

### D4. One account = one laptop

The server pins each account to the identity key it registered with. alice can't log in
from another laptop's `keys\` folder. To use another laptop, register a different name there.

---

## Part E: using it

### E1. Start a chat and verify it

In bob's terminal:
```
/chat alice
```

Both sides print:
```
First contact with alice: their identity key has been saved...
Encrypted session with alice ready. Safety number: 58942 80405 78963 ... | X25519 + ML-KEM-768 (post-quantum hybrid) + Double Ratchet
```

To verify, compare the **safety number**: bob runs `/safety alice`, and alice runs `/safety bob`.
The 30 digits must be identical on both screens. That proves nobody is in the middle.

### E2. All commands

| Command | What it does |
|---|---|
| `/chat bob` | new signed, post-quantum, ratcheted session with bob; makes him the active chat |
| *(any text)* | sent encrypted to the active chat only. The prompt shows who: `[to bob]>` |
| `@dhinakar hello` | one message to dhinakar without switching |
| `/switch dhinakar` | change the active chat (no new handshake) |
| `/sessions` | list sessions (`*` = active) with safety numbers and the suite |
| `/safety bob` | show the safety number for bob |
| `/send bob C:\Users\me\notes.pdf` | send a file (max 50 MB). Bob receives it in `downloads\bob\` |
| `/trust bob` | accept bob's **changed** identity key, only after checking the safety number with him |
| `/who` | who is online |
| `/quit` | exit |

GUI equivalents:
- the **Conversations** list, the **Start encrypted chat** box, the **Send to <name>** button
- **Send file...**, **Show safety number**, **Trust changed key...**

### E3. Optional client flags

| Flag | Use |
|---|---|
| `--no-pq` | classic X25519 only (no ML-KEM); for comparisons |
| `--keys-dir keys_demo` | use a different key folder (demo runs) |
| `--ca path\to\ca.pem` | if `ca.pem` isn't in `certs\` |
| `--no-tls`, `--insecure` | **attack demo only**, see Part G |

---

## Part F: demos for the review

| Demo | Command | Shows |
|---|---|---|
| Double Ratchet | `python -m demos.ratchet_demo` | handshake sizes, a new key per message, and that leaking one key exposes exactly one message |
| Wireshark | see `docs\wireshark_guide.md` | only ciphertext on the wire; TLS on vs off |
| Attacks | see Part G | MITM, replay and bit-flip: each works against insecure clients and fails against secure ones |
| Brute force | log in with a wrong password 6 times | `Too many failed logins` and `LOGIN_LOCKOUT` in `logs\security.jsonl` |
| Firewall hook | put a client's IP in `data\blacklist.txt`, then connect | dropped before TLS, `BLOCKED_CONNECTION` logged |

---

## Part G: attack demo (TLS off, separate setup)

Use **4 terminals**. Give each run its own name (`insecure`, `secure`, `forge`), so it gets
a fresh database and fresh keys. Restart T1 and T2 between runs.

```powershell
# T1 server (no TLS, demo database)
python -m server.relay_server --no-tls --port 9000 --db data/demo_RUN.db
# T2 attack proxy (pick one)
python -m attacks.mitm_proxy    --listen 9100 --server-port 9000
python -m attacks.replay_attack --listen 9100 --server-port 9000 --copies 2 --delay 2
python -m attacks.tamper_attack --listen 9100 --server-port 9000 --position 4 --from-char 1 --to-char 9
# T3 / T4 clients -> connect to the PROXY port 9100; add --insecure for the "attack works" run
python -m client.cli_client --name alice --port 9100 --no-tls --keys-dir keys_RUN --register [--insecure]
python -m client.cli_client --name bob   --port 9100 --no-tls --keys-dir keys_RUN --register [--insecure]
```

Then in bob's window, `/chat alice`, and send:

| Attack | Message to send | `--insecure` clients | Secure clients |
|---|---|---|---|
| MITM | `the vault code is 4321` | proxy prints `INTERCEPTED ...` | alice: `SIG_FAIL ... Session refused` |
| Replay | `pay 100 to alice` | alice sees it 3× | alice sees it once, then `REPLAY_OR_REORDER` ×2 |
| Tamper | `pay 100 to bob` | alice sees **`pay 900 to bob`** | alice: `TAG_FAIL`; after 3: session closed |

Full runbook with the `--forge-identity` variant and the screenshot list: `docs\attack_demo.md`.

---

## Part H: benchmarks for the report

```powershell
python -m benchmarks.bench_crypto
```

This takes about 1 minute and writes to `benchmarks\results\`:
- `results.md`: a table to paste into the report
- `results.csv`: the raw numbers
- `handshake.png`, `message_cost.png`, `round_trip.png`: the charts

Run it on **your** laptop, close other heavy apps first, and state the laptop model in the report.

---

## Part I: Docker (optional, not yet tested)

Needs Docker Desktop. From the project folder:

```powershell
docker compose up -d relay                # builds the image, creates certs, starts the server
docker compose run --rm alice --register  # terminal 2
docker compose run --rm bob --register    # terminal 3 (drop --register next time)
docker compose down                       # stop   (add -v to wipe accounts, keys, certs)
```
The relay is also published on port 9000. Laptops connecting from outside Docker need the
container's CA (`docker compose cp relay:/app/certs/ca.pem certs/ca.pem`) and
`--host <SERVER-IP>`.

---

## Part J: where everything lives

| Folder | Contents | Laptop | Commit to Git? |
|---|---|---|---|
| `certs\` | TLS certificates | server: all 4; clients: `ca.pem` | **no** |
| `data\` | `users.db`, `blacklist.txt`, demo databases | server | **no** |
| `keys\<user>\` | encrypted identity key + known contacts | where that user registered | **no** |
| `logs\` | `security.jsonl` (server), `security-<user>.jsonl` (clients) | each | **no** |
| `downloads\<user>\` | received files | each client | **no** |
| `benchmarks\results\` | benchmark output | yours | **no** |

All of these are already in `.gitignore`.

---

## Part K: reset

| Goal | Steps (stop the server and clients first) |
|---|---|
| Forget one user on one laptop | `Remove-Item -Recurse keys\bob`, then delete `data\users.db` on the server (removes **all** accounts) and everyone registers again |
| Fresh start, keep the certificate | `Remove-Item -Recurse data, keys, logs, downloads` |
| New certificate (new IP) | `Remove-Item -Recurse certs`, rerun Part B2, recopy `ca.pem` |
| A contact reset their keys | check the safety number with them, then `/trust <name>` |

---

## Part L: troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `No certificate in certs/` (server) | Part B2 not done | `python scripts/make_certs.py --ip <SERVER-IP>` |
| `CA certificate certs/ca.pem not found` (client) | `ca.pem` not copied | Part B3 |
| `certificate verify failed` / hostname mismatch | `--host` isn't an IP in the certificate | use the IP from B2, or rerun B2 with the new IP and recopy `ca.pem` |
| `No identity key for 'bob' on this machine` | first time, without `--register` | add `--register` |
| `Wrong key passphrase` | wrong passphrase for `keys\<user>` | retype it; if forgotten, reset that user (Part K) |
| `Invalid username or password` | wrong password, or never registered on this server | check the password; `--register` if new |
| `Identity key does not match this account` | logging in from another laptop or keys folder | use the laptop you registered on, or a new name |
| `Username 'x' is already registered` | `--register` a second time | drop `--register` |
| `Too many failed logins` | 5 wrong passwords in a minute | wait 60 seconds (brute-force protection) |
| `Refused an old (replayed?) key exchange` | laptop clocks more than 5 minutes apart | Settings → Time & language → **Sync now** on both laptops |
| `HANDSHAKE_TIMEOUT: alice did not answer` | alice offline, or she refused your key (check her screen) | `/who`; compare safety numbers; `/trust` on her side if legitimate |
| `identity key has CHANGED ... Session refused` | the contact reset their keys, or an attacker | verify the safety number in person, then `/trust <name>` |
| `uses --insecure mode but you use secure mode` | one client started with `--insecure` | start both the same way |
| `Post-quantum mode unavailable` | `cryptography` older than 47 | `pip install -U cryptography` |
| Client can't connect at all (timeout) | Windows Firewall, different Wi-Fi, or a wrong IP | Part B4; same Wi-Fi; `ping <SERVER-IP>` |
| `Set-ExecutionPolicy` / script errors | PowerShell blocks venv activation | use the activation line in A4 exactly as written |

---

## Quick start: the 60-second version

```powershell
# server laptop, once
python scripts/make_certs.py --ip <SERVER-IP>        # then copy certs\ca.pem to client laptops
# server laptop, every time
python -m server.relay_server --host 0.0.0.0 --port 9000
# each user, first time (later: drop --register)
python -m client.cli_client --name alice --host <SERVER-IP> --port 9000 --register
# chat
/chat bob      /safety bob      /send bob C:\file.pdf      /quit
```
