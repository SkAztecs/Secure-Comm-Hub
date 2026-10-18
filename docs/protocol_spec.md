# Protocol specification (Phase 3)

Every message is a **length-prefixed frame** holding a JSON **envelope** the server
can read. For chat and files, the envelope carries an **encrypted packet** only the
two clients can read:
- Since Phase 2, every hop runs inside **TLS 1.3**.
- Since Phase 3:
  - the key exchange is a **post-quantum hybrid** (X25519 + ML-KEM-768);
  - every message is encrypted with its own key from a **Double Ratchet**.

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
| KEY_INIT | client → client | `pub` (X25519, 32 B), `kem_pub` (ML-KEM-768, 1184 B, PQ mode), `ts` (8 B Unix time), `id_pub`, `sig` (Ed25519, 64 B), `insecure` (bool) |
| KEY_RESP | client → client | `pub`, `kem_ct` (ML-KEM ciphertext, 1088 B, PQ mode), `id_pub`, `sig`, `insecure` |
| CHAT | client → client | `packet` (b64, v2 packet) |
| FILE_CHUNK | client → client | `packet` (b64, v2 packet of type 0x11) |
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

## 5. Handshake (signed, post-quantum hybrid)

1. **Initiator A** makes a fresh X25519 pair and an ML-KEM-768 pair, then sends
   `KEY_INIT {pub_A, kem_pub_A, ts, id_A, sig_A}`.
2. **Responder B:**
   1. Verifies `sig_A` (fail → `SIG_FAIL`) and checks `id_A` with trust-on-first-use.
      It also checks **freshness**: `ts` must be within 5 minutes of its own clock, and
      `pub_A` must not have been seen before. Otherwise the KEY_INIT is a replay
      (`REPLAY_OR_REORDER`) and the working session is kept.
   2. Makes its own X25519 pair and computes `x = X25519(priv_B, pub_A)`.
   3. Runs `(pq, kem_ct) = ML-KEM.Encaps(kem_pub_A)`.
   4. Replies `KEY_RESP {pub_B, kem_ct, id_B, sig_B}`.
3. **A** verifies `sig_B` and `id_B`, then computes `x = X25519(priv_A, pub_B)` and `pq = ML-KEM.Decaps(kem_ct)`.

**Signed transcripts.** Fields are encoded as `name | 4-byte length | value`, sorted by name.

| Signature | Covers |
|---|---|
| `sig_A` | `"KEY_INIT|v2|" + A + "|" + B + "|" + fields(KEY_INIT)` |
| `sig_B` | `"KEY_RESP|v2|" + A + "|" + B + "|" + fields(KEY_INIT) + "||" + fields(KEY_RESP)` |

What the signatures prevent:

| Attack | Why it fails |
|---|---|
| Changing or **removing** any field, including `kem_pub` | the signature no longer verifies, so the post-quantum part can't be silently stripped (downgrade attack) |
| Reusing a signed `KEY_INIT` towards another user | the names are inside the signature |
| Replaying an old reply | `sig_B` covers this handshake's `KEY_INIT` |
| Replaying an old signed `KEY_INIT` (e.g. a malicious relay) | the signed `ts` is too old, or `pub_A` was already seen |

**Modes:**
- **Classic** (`--no-pq`, or `cryptography` < 47): no `kem_pub` / `kem_ct`, and `pq = ""`.
- **Refusing downgrades:** an initiator that offered `kem_pub` refuses a reply without `kem_ct`.
- **Insecure flag:** `insecure` must match on both sides, otherwise the session is refused.
- **Simultaneous start:** if both sides start at the same moment, the alphabetically smaller username stays the initiator.

## 6. Key derivation → Double Ratchet

```
salt = SHA256( sorted(pub_A, pub_B) concatenated )
okm  = HKDF-SHA256(ikm = x || pq, salt, info = "p1-chat-v2", length = 64)
root_key        = okm[0:32]
responder_chain = okm[32:64]     # lets B send before the first DH ratchet step
```

**Initial ratchet state:**

| Side | Ratchet key | Root and chains |
|---|---|---|
| Initiator A | a **fresh** X25519 pair `R_A` | `root, send_chain = KDF_RK(root_key, DH(R_A, pub_B))`; `recv_chain = responder_chain` |
| Responder B | its handshake pair (`pub_B`), deleted at B's first DH ratchet step | `root = root_key`; `send_chain = responder_chain` |

**Ratchet functions:**

```
KDF_RK(rk, dh)  = HKDF-SHA256(salt = rk, ikm = dh, info = "p1-ratchet-root", 64) -> (new rk, chain key)
KDF_CK(ck)      = (HMAC-SHA256(ck, 0x02) -> next ck,  HMAC-SHA256(ck, 0x01) -> message key)
message key  -> HKDF(info = "p1-message-key", 44) -> AES-256 key (32) + nonce (12)
```

**Ratchet rules:**
- **Every message:** advance the sending chain with `KDF_CK`, which gives a new message key.
- **New ratchet key received** (the conversation changed direction):
  1. Save the keys of messages still in flight in the old chain (`pn`).
  2. Derive the new receiving chain from `DH(my key, their new key)`.
  3. Make a new key pair and derive the new sending chain from it.
  4. The old private key is gone.
- **Out-of-order messages:** up to **50** skipped keys per chain and **200** stored in total.
- **All-or-nothing decryption:** if decryption fails, the ratchet state is restored exactly, so one forged packet can't desynchronise a conversation.

## 7. Encrypted packet v2 (inside `packet`)

| Field | Size | Purpose |
|---|---|---|
| ver | 1 B | `0x02` |
| type | 1 B | `0x10` CHAT, `0x11` FILE_CHUNK |
| dh | 32 B | sender's current ratchet public key |
| pn | 4 B | number of messages in the sender's previous chain |
| n | 4 B | message number in the current chain |
| ciphertext + tag | variable + 16 B | AES-256-GCM with this message's own key and nonce |

The 42-byte header is the GCM associated data, so it is authenticated but not encrypted.
The overhead per message is 58 bytes.

`--insecure` demo mode still uses the **v1** packet: `ver 0x01 | type | seq 8 B | nonce 12 B | AES-CTR ciphertext`, with no tag.

## 8. Receiver rules

| Situation | What happens |
|---|---|
| GCM tag fails | rejected, `TAG_FAIL`. 3 in one session → session closed, `SESSION_CLOSED_TAG_FAILS` |
| Message number already used in this chain, and not a saved late message | rejected, `REPLAY_OR_REORDER` |
| More than 50 skipped messages | rejected |
| Malformed JSON, too-short packet, wrong version | rejected; the client keeps running |

## 9. Rekeying

- The Double Ratchet renews keys every time the conversation changes direction.
- On top of that, a full new handshake runs after **1,000 messages** or **1 hour**. This also refreshes the post-quantum secret, which the ratchet alone doesn't.
- The new session replaces the old one only after `KEY_RESP` arrives.

## 9b. File transfer

The file is sent as encrypted `FILE_CHUNK` packets (type `0x11`), one ratchet key per packet.
The plaintext of each packet is `JSON header + "\n" + raw bytes`:

| Piece | Header | Body |
|---|---|---|
| start | `{"kind":"start","id","name","size","sha256","chunks"}` | none |
| chunk | `{"kind":"chunk","id","index"}` | up to 32 KB of the file |
| end | `{"kind":"end","id"}` | none |

**Receiver rules:**
- Accepts files up to **50 MB**, at most **4 at a time per sender**, and refuses duplicate transfer ids.
- Names the temporary file with its **own random value**, never the sender's id.
- Deletes unfinished transfers after 10 minutes, or when the session closes.
- Reduces the file name to a safe base name, so a name can't escape the folder.
- Writes the data to `downloads/<user>/.<id>.part` while receiving.
- Checks the chunk order, the total size and the **SHA-256** of the whole file.
- Keeps the file only if every check passes; otherwise it deletes it and logs `FILE_TRANSFER_FAIL`.

## 10. Message type codes

| Code | Name |
|---|---|
| 0x01 | HELLO |
| 0x02 | KEY_INIT |
| 0x03 | KEY_RESP |
| 0x10 | CHAT |
| 0x11 | FILE_CHUNK |
| 0x20 | REKEY (reserved; rekeying reuses KEY_INIT) |
| 0x30 | ACK |
| 0x7F | ERROR |

## 11. Demo-only modes (never for real use)

| Flag | What it disables |
|---|---|
| `--no-tls` | TLS: envelopes, usernames and passwords travel in plain text |
| `--insecure` | signature and identity checks, replay check, Double Ratchet and post-quantum; uses one static key with **AES-256-CTR without a tag**, so ciphertext is malleable |
