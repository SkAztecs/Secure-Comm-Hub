# Protocol specification v1 (Phase 2)

Every message is a **length-prefixed frame** holding a JSON **envelope** the server
can read. For chat, the envelope carries an **AES-256-GCM packet** only the two
clients can read. From Phase 2, every hop runs inside **TLS 1.3**.

## 0. Connection order (server side)

1. **Firewall check:** IP on Pillar 3's blacklist → closed, `BLOCKED_CONNECTION`
2. **TLS 1.3 handshake:** fails → `TLS_FAIL`
3. **HELLO within 10 s:** missing → `HANDSHAKE_TIMEOUT`
4. **Login / register:** failure → `LOGIN_FAIL`; 5 per minute from one IP → `LOGIN_LOCKOUT` (60 s)
5. **Routing:** the server overwrites `from` with the logged-in name and forwards by `to`

## 1. Frame on the wire

```
[4-byte big-endian length][UTF-8 JSON envelope]
```
Frames larger than 64 KB are rejected (`FRAME_TOO_LARGE`) and the connection is closed.

## 2. Envelopes

| type | direction | fields |
|---|---|---|
| HELLO | client → server | `from`, `mode` (`login`/`register`), `password`, `id_pub` (b64 Ed25519, 32 B) |
| WELCOME | server → client | `to`, `online` |
| WHO | both | `online` (in reply) |
| KEY_INIT | client → client | `pub` (b64 X25519, 32 B), `id_pub`, `sig` (b64 Ed25519, 64 B) |
| KEY_RESP | client → client | `pub`, `id_pub`, `sig` |
| CHAT | client → client | `packet` (b64) |
| ERROR | server → client | `reason` |

## 3. Accounts

- Passwords are at least 8 characters and are stored as **Argon2id** hashes (argon2-cffi defaults, RFC 9106).
- Every login failure returns the same message: `Invalid username or password`. Unknown users are checked against a dummy hash so the response time is the same.
- Each account is pinned to the `id_pub` it registered with. A login with a different identity key is refused.

## 4. Identity keys

- Each user has one long-term **Ed25519** key pair, stored in `keys/<user>/identity.json`.
- The private key is encrypted with `AES-256-GCM(key = scrypt(passphrase, salt; n=2^15, r=8, p=1))`, using the username as AAD.
- **Trust on first use:** the first `id_pub` seen for a peer is saved in `known_peers.json`.
  - A different key later → `IDENTITY_CHANGED`, the session is refused, and the user must run `/trust <peer>`.
- **Safety number** = SHA-256(sorted identity keys), shown as 6 groups of 5 digits. Both users must see the same number.

## 5. Handshake

1. Initiator A makes an ephemeral X25519 pair and sends `KEY_INIT {pub_A, id_A, sig_A}`.
   - `sig_A` = Ed25519 signature over `"KEY_INIT|v1|" + A + "|" + B + "|" + pub_A`.
2. Responder B:
   1. Verifies `sig_A` (fail → `SIG_FAIL`) and checks `id_A` with trust-on-first-use.
   2. Makes its own pair and computes the keys.
   3. Replies `KEY_RESP {pub_B, id_B, sig_B}`, where `sig_B` covers `"KEY_RESP|v1|" + A + "|" + B + "|" + pub_A + pub_B`.
3. A verifies `sig_B` and `id_B`, then computes the keys.
4. Both delete their ephemeral private keys (**forward secrecy**).

Signing the names stops a signed message from being reused towards another user.
Including `pub_A` in `sig_B` ties the reply to this exact handshake.

If both sides start a handshake at the same moment, the alphabetically smaller
username stays the initiator.

## 6. Key derivation

```
salt = SHA256( sorted(pub_A, pub_B) concatenated )
okm  = HKDF-SHA256(ikm = shared, salt = salt, info = "p1-chat-v1", length = 64)
key_initiator_to_responder = okm[0:32]
key_responder_to_initiator = okm[32:64]
```

## 7. Encrypted packet (inside `packet`)

| Field | Size | Purpose |
|---|---|---|
| ver | 1 B | `0x01` |
| type | 1 B | message type code (CHAT = `0x10`) |
| seq | 8 B | per-direction counter, starts at 0 |
| nonce | 12 B | `00 00 00 00` + seq (8 B), never repeats under one key |
| ciphertext | variable | AES-256-GCM output |
| tag | 16 B | GCM authentication tag |

The 10-byte header is the GCM **associated data**. The receiver also checks that `nonce` matches `seq`.

## 8. Receiver rules

- GCM tag fails → rejected, `TAG_FAIL`. 3 in one session → session closed, `SESSION_CLOSED_TAG_FAILS`.
- `seq` ≠ next expected → rejected, `REPLAY_OR_REORDER`.
- Malformed JSON, a packet that's too short, or the wrong version → rejected; the client keeps running.

## 9. Rekeying

- Before sending, a client starts a fresh handshake if the session has sent **1,000 messages** or is **1 hour** old.
- The new keys replace the old ones only after `KEY_RESP` arrives, so messages still in flight under the old keys keep decrypting.
- `seq` restarts at 0 under the new keys.

## 10. Message type codes

| Code | Name |
|---|---|
| 0x01 | HELLO |
| 0x02 | KEY_INIT |
| 0x03 | KEY_RESP |
| 0x10 | CHAT |
| 0x11 | FILE_CHUNK (Phase 3) |
| 0x20 | REKEY (reserved; rekeying reuses KEY_INIT) |
| 0x30 | ACK |
| 0x7F | ERROR |

## 11. Demo-only modes (never for real use)

| Flag | What it disables |
|---|---|
| `--no-tls` | TLS: envelopes, usernames and passwords travel in plain text |
| `--insecure` | signature and identity checks, replay check; uses **AES-256-CTR without a tag**, so ciphertext is malleable |
