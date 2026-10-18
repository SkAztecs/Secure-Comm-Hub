# Phase 2 attack demo — runbook

Each attack is run **twice**:

1. Against clients started with `--insecure`, where the attack **works**.
2. Against normal clients, where the attack **fails** and is written to the security log.

All attack runs need TLS **off** (`--no-tls` on the server and both clients).
With TLS on, the proxy can't even read the frames. That's the first line of
defence, and you should say so in the viva.

Use 4 terminals, all in the `secure-messaging` folder with the venv active.
These commands are for one laptop. For several laptops, replace `127.0.0.1` with
the server's IP and run the proxy on any machine the clients can reach.

```
T1  server   python -m server.relay_server --no-tls --port 9000 --db data/demo_RUN.db
T2  attack   python -m attacks.<attack> --listen 9100 --server-port 9000
T3  alice    python -m client.cli_client --name alice --port 9100 --no-tls --keys-dir keys_RUN [--insecure] [--register]
T4  bob      python -m client.cli_client --name bob   --port 9100 --no-tls --keys-dir keys_RUN [--insecure] [--register]
```

The clients connect to **9100**, which is the proxy, not the real server.

Give every run its own `RUN` name (for example `insecure`, `secure`, `forge`). Each run
then has a fresh user database and fresh identity keys:

- Add `--register` the first time each user logs in during that run.
- If you reuse a database with a different keys folder, login fails with
  `Identity key does not match this account`. The server pins each account to the
  identity key it registered with.
- Separate key folders also stop trust-on-first-use from remembering keys from an
  earlier run.

Restart T1 and T2 between runs (Ctrl+C, then start them again with the new `RUN` name).

---

## Attack 1: man-in-the-middle on the key exchange

Since Phase 3, the proxy copies the **whole** handshake: X25519, ML-KEM-768 and the
Double Ratchet. Post-quantum crypto alone does not stop a man-in-the-middle; only
the signatures and identity checks do. That's a good point to make in the viva.

`python -m attacks.mitm_proxy --listen 9100 --server-port 9000`

| Run | What to do | What you see |
|---|---|---|
| Insecure | bob: `/chat alice`, then type `the vault code is 4321` | T2 prints `INTERCEPTED bob -> alice: 'the vault code is 4321'`, and alice still receives it normally |
| Secure | bob: `/chat alice` | alice: `SIG_FAIL: the key exchange with bob was NOT signed by bob. Possible man-in-the-middle. Session refused.` After 10 s bob gets `HANDSHAKE_TIMEOUT: alice did not answer`. `logs/security-alice.jsonl` has `SIG_FAIL` |

Extra: `python -m attacks.mitm_proxy --forge-identity`. Here the attacker replaces the identity key as well and signs with its own key.

- **First contact:** the handshake succeeds, but `/safety alice` on bob's side and `/safety bob` on alice's side show **different numbers**. This is why users are told to compare safety numbers.
- **If alice and bob have talked before:** you get `WARNING: bob's identity key has CHANGED ... Session refused` and an `IDENTITY_CHANGED` log event. To show this, do a secure run without the proxy first (clients on port 9000) so they save each other's real keys. Then reconnect through the `--forge-identity` proxy using the same `RUN` name, without `--register`.

## Attack 2: replay

`python -m attacks.replay_attack --listen 9100 --server-port 9000 --copies 2 --delay 2`

| Run | What to do | What you see |
|---|---|---|
| Insecure | bob: `/chat alice`, then `pay 100 to alice` | alice sees `pay 100 to alice` **3 times** |
| Secure | same | alice sees it once, then twice `Rejected a message: REPLAY_OR_REORDER: expected seq 1, got 0`, and a `REPLAY_OR_REORDER` log event |

## Attack 3: bit-flipping (tampering)

`python -m attacks.tamper_attack --listen 9100 --server-port 9000 --position 4 --from-char 1 --to-char 9`

| Run | What to do | What you see |
|---|---|---|
| Insecure (AES-CTR, no tag) | bob: `/chat alice`, then exactly `pay 100 to bob` | alice sees **`pay 900 to bob`**, with no warning |
| Secure (AES-GCM) | same | alice: `Rejected a message: TAG_FAIL (message was tampered with)`. After 3 such messages: `Session with bob CLOSED`, plus `TAG_FAIL` and `SESSION_CLOSED_TAG_FAILS` log events |

## Bonus: password brute force (no proxy needed, TLS can stay on)

Try to log in as an existing user with a wrong password 5 times. The 6th try gets
`Too many failed logins. Try again in a minute.`, and `logs/security.jsonl` shows
`LOGIN_FAIL` ×5 + `LOGIN_LOCKOUT`. These events are what Pillar 2 learns from.

## Bonus: what TLS hides

Run any proxy with the server and clients on TLS (no `--no-tls`). The proxy prints
`can't read this traffic (is TLS on?)` and the login fails. In Wireshark, the
password and usernames that were readable in plain-TCP mode are gone.

---

## Screenshots for the review

| # | Screenshot |
|---|---|
| 1 | MITM insecure: proxy terminal showing `INTERCEPTED ...` |
| 2 | MITM secure: alice's `SIG_FAIL ... Session refused` |
| 3 | Forged identity: the two different safety numbers side by side |
| 4 | Replay insecure (3 copies) vs secure (`REPLAY_OR_REORDER`) |
| 5 | Tamper insecure (`pay 900`) vs secure (`TAG_FAIL`) |
| 6 | `logs/security.jsonl` / `security-alice.jsonl` with the events |
| 7 | Brute-force lockout message |

The same scenarios run automatically in `tests/test_attacks.py` (`pytest -v tests/test_attacks.py`).
