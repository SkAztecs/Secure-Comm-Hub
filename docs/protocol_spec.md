# Protocol specification — v1 (Phase 1)

Every message is a **length-prefixed frame** holding a small JSON **envelope** the
server can read, and (for chat) an **AES-256-GCM packet** only the two clients can read.

## 1. Frame on the wire

```
[4-byte big-endian length][UTF-8 JSON envelope]
```
Frames larger than 64 KB are rejected and the connection is closed.

## 2. Envelopes

| type | direction | fields |
|---|---|---|
| HELLO | client → server | `from` |
| WELCOME | server → client | `to`, `online` (list) |
| WHO | both | `online` (in reply) |
| KEY_INIT | client → client | `from`, `to`, `pub` (base64, 32 B X25519) |
| KEY_RESP | client → client | `from`, `to`, `pub` |
| CHAT | client → client | `from`, `to`, `packet` (base64) |
| ERROR | server → client | `reason` |

The server **overwrites `from`** with the name the connection registered with,
so a client cannot pretend to be someone else.

## 3. Handshake

1. Initiator A makes an ephemeral X25519 key pair and sends `KEY_INIT {pub_A}`.
2. Responder B makes its own pair, computes the shared secret, replies `KEY_RESP {pub_B}`.
3. Both compute `shared = X25519(my_private, peer_public)`.
4. Both derive keys (below) and **delete their ephemeral private key** (forward secrecy).

Phase 2 adds: Ed25519 signatures on `pub`, safety numbers, TLS 1.3 per hop.

## 4. Key derivation

```
salt = SHA256( sorted(pub_A, pub_B) concatenated )
okm  = HKDF-SHA256(ikm = shared, salt = salt, info = "p1-chat-v1", length = 64)
key_initiator_to_responder = okm[0:32]
key_responder_to_initiator = okm[32:64]
```

## 5. Encrypted packet (inside `packet`)

| Field | Size | Purpose |
|---|---|---|
| ver | 1 B | `0x01` |
| type | 1 B | message type code (CHAT = `0x10`) |
| seq | 8 B | per-direction counter, starts at 0 |
| nonce | 12 B | `00 00 00 00` + seq (8 B) — never repeats under one key |
| ciphertext | variable | AES-256-GCM output |
| tag | 16 B | GCM authentication tag |

The 10-byte header (`ver`, `type`, `seq`) is the GCM **associated data**: changing any
header bit makes decryption fail. The receiver also checks that `nonce` matches `seq`.

## 6. Message type codes

| Code | Name |
|---|---|
| 0x01 | HELLO |
| 0x02 | KEY_INIT |
| 0x03 | KEY_RESP |
| 0x10 | CHAT |
| 0x11 | FILE_CHUNK (Phase 3) |
| 0x20 | REKEY (Phase 2) |
| 0x30 | ACK |
| 0x7F | ERROR |

## 7. Receiver rules

- GCM tag fails → message rejected (`TAG_FAIL`).
- `seq` ≠ next expected → message rejected (`REPLAY_OR_REORDER`).
- Malformed JSON / packet too short / wrong version → rejected, client keeps running.
