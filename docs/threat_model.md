# Threat model (STRIDE): Pillar 1 Secure Messaging

**Scope:** the relay server, the CLI/GUI clients and the protocol between them,
as built at the end of Phase 3.

## Assets

| Asset | Why it matters |
|---|---|
| Message and file contents | the main thing users want kept secret |
| Long-term identity keys (Ed25519) | whoever holds one can impersonate that user |
| Account passwords | let someone log in as a user |
| Session and message keys | decrypt conversations |
| Metadata (who talks to whom, when) | reveals relationships even without content |
| Server availability | no server = nobody can chat |

## Trust assumptions

1. **The server is honest-but-curious.** It routes messages correctly, but may try to read them.
   The design never gives it a key that can decrypt messages.
2. **Endpoints are not compromised.** Malware on a user's laptop can read the screen and keys; no messaging protocol can stop that.
3. **Users compare safety numbers** on first contact, at least for important contacts. Without this, trust-on-first-use can be fooled once (see S2).
4. **The network is hostile.** Anyone on the Wi-Fi can sniff, drop, replay or modify packets.
5. **Cryptographic primitives are sound.**
   - AES-256-GCM, X25519, Ed25519, HKDF-SHA256, Argon2id, scrypt and ML-KEM-768 come from audited libraries (`cryptography`, `argon2-cffi`).
   - We wrote none of them ourselves.

## Trust boundaries

```
 [Client A] ==TLS 1.3==> [Relay server] ==TLS 1.3==> [Client B]
      \_______________ end-to-end AES-GCM (Double Ratchet) ___________/
 boundary 1: network (hostile)      boundary 2: server (curious)
```

## STRIDE analysis

| # | Threat | Example attack | Mitigation in this design | Residual risk |
|---|---|---|---|---|
| **S1** | **Spoofing** a user at the server | guess or steal alice's password | Argon2id hashes; 5 failures/min → 60 s IP lockout; generic error messages; accounts pinned to their identity key, so a stolen password alone is not enough | weak passwords; a distributed brute force from many IPs bypasses the per-IP limit (Pillar 2 can detect this) |
| **S2** | **Spoofing** a peer (MITM in the key exchange) | attacker swaps ephemeral keys | every handshake field is **signed with Ed25519**; trust-on-first-use pins identity keys; safety numbers | very first contact: an attacker who forges a whole identity is caught **only** if users compare safety numbers (shown in the demo) |
| **S3** | **Spoofing** the server | fake server on the LAN | TLS 1.3 with a private CA; clients pin `ca.pem` and check the hostname | the CA private key leaks from the server machine |
| **T1** | **Tampering** with messages | flip bits ("pay 100" → "pay 900") | AES-256-GCM authenticates the ciphertext **and** the header (AAD); a session closes after 3 tag failures | none known; the attacker can only cause drops |
| **T2** | **Tampering** with the ratchet state | inject a packet with a fake ratchet key | decrypt is all-or-nothing; the state is restored on failure | none known |
| **T3** | **Tampering** with files | alter or truncate a transfer | each chunk is GCM-authenticated; the whole file's SHA-256 is checked; incomplete or mismatched files are deleted | none known |
| **T4** | **Downgrade** (strip post-quantum) | remove `kem_pub` to force classic X25519 | `kem_pub` / `kem_ct` are inside the signed transcript; an initiator that offered PQ refuses a reply without it | both users choosing `--no-pq` |
| **R1** | **Repudiation** | "I never sent that" | not a goal: like Signal, messages are deniable (symmetric keys); the server logs who connected and when | intended trade-off |
| **I1** | **Information disclosure**: content | sniff the network or read the server | end-to-end AES-256-GCM; the server never has the keys; TLS 1.3 per hop | endpoint compromise (assumption 2) |
| **I2** | **Disclosure**: past messages after a key leak | steal today's keys | ephemeral X25519 + **Double Ratchet** (a new key per message, old keys deleted) → forward secrecy | messages still on screen or in a terminal log |
| **I3** | **Disclosure**: future quantum computer | record traffic now, break X25519 later | **X25519 + ML-KEM-768 hybrid**: the root key needs both secrets | identity signatures (Ed25519) are not post-quantum; this matters for live MITM, not for recorded traffic |
| **I4** | **Disclosure**: metadata | see who talks to whom | TLS hides usernames and types from the network | the server itself sees who talks to whom and when |
| **I5** | **Disclosure**: stolen laptop | copy the `keys\` folder | identity key encrypted with a scrypt-derived key (passphrase) | weak passphrase → offline guessing |
| **I6** | **Disclosure / tampering**: path traversal via a file name or transfer id | send `../../evil.dll`, or a transfer id of `/../../x` | names are reduced to a safe base name inside `downloads\`; temporary files use the receiver's own random name (fixed after code review) | none known |
| **D1** | **Denial of service**: floods | SYN flood, connection flood | 64 KB frame limit; 10 s HELLO timeout; asyncio (no thread per client); **Pillar 2 detects, Pillar 3 blocks before TLS** | volumetric floods beyond the laptop's bandwidth |
| **D2** | **DoS**: oversized or garbage frames | send a 4 GB length header | the length is checked **before** reading; malformed frames are logged and dropped | none known |
| **D3** | **DoS**: ratchet skip | claim message number 1,000,000 | at most 50 skipped keys per chain, 200 stored in total | none known |
| **D4** | **DoS**: malformed messages | nested JSON or wrong types inside an encrypted file header | every message is handled in isolation; any error is logged as `MALFORMED_FRAME` and the client keeps running (fixed after code review) | none known |
| **D5** | **DoS**: file-transfer flood | hundreds of "start" pieces | at most 4 transfers per sender, duplicates refused, stale ones cleaned up after 10 minutes | a peer can still send 4 × 50 MB |
| **D6** | **DoS**: replayed `KEY_INIT` | a malicious relay replays an old signed handshake to break a working session | signed timestamp (±5 min) + seen-key check; the old session stays (fixed after code review) | laptop clocks more than 5 minutes apart cause false refusals |
| **E1** | **Elevation of privilege**: impersonating `from` | a client sets `"from": "bob"` | the server overwrites `from` with the authenticated username | none known |
| **E2** | **Elevation**: demo modes left on | `--insecure` / `--no-tls` in real use | loud warnings; insecure and secure clients refuse each other | a user ignoring the warnings |

## What we deliberately did NOT do (and why)

| Not done | Reason |
|---|---|
| Header encryption (hide ratchet keys and message numbers) | adds complexity; TLS already hides headers from the network |
| Post-quantum signatures (ML-DSA) | signatures only matter during a live handshake; harvest-now-decrypt-later targets the key exchange, which is hybrid |
| Hiding metadata from the server | needs sealed sender / mixnets, out of scope for a course project |
| Offline message queue | would need prekeys (X3DH) because the handshake needs both users online |
| Multi-device per account | each account is pinned to one identity key by design |
