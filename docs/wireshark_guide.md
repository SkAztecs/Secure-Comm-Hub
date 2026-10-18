# Wireshark proof — "the wire only carries ciphertext"

This is the Phase 1 evidence for the review (Step 9).

## Same laptop (quickest)

1. Install Wireshark. On Windows also install **Npcap** with
   "Support loopback traffic capture" ticked.
2. Start capturing on the **loopback** adapter
   (Windows: `Adapter for loopback traffic capture`, macOS: `lo0`, Linux: `lo`).
3. Display filter: `tcp.port == 9000`
4. Start the server and two clients, run `/chat`, send a message such as
   `MEET AT GATE 3 AT 5PM`.
5. In Wireshark: **Edit → Find Packet → String → "GATE 3"** (search in packet bytes).
   It should find **nothing**.
6. Right-click any packet → **Follow → TCP Stream**. You will see:
   - readable JSON envelopes: `{"type": "CHAT", "from": "bob", "to": "alice", "packet": "AQ..."}`
   - the `packet` value is base64 of `ver|type|seq|nonce|ciphertext|tag` — unreadable.

## Two or three laptops (better for the demo)

Run the server on laptop 1 with `--host 0.0.0.0`, clients on laptops 2 and 3 with
`--host <laptop1 IP>`, and capture on laptop 1's Wi-Fi adapter with the same filter.

## Screenshots to take for the report

| # | Screenshot | What it proves |
|---|---|---|
| 1 | Both clients showing the same session fingerprint | Both derived the same keys |
| 2 | Find-packet search for the message text returning nothing | No plaintext on the wire |
| 3 | Follow TCP Stream showing the base64 `packet` | Server only routes ciphertext |
| 4 | Server log lines `ROUTE KEY_INIT / KEY_RESP / CHAT` | Server routes, never decrypts |

## Honest note for the viva
In Phase 1 the routing envelope (usernames, message type) is visible on the wire.
Phase 2 wraps each hop in **TLS 1.3**, which hides that metadata too.
