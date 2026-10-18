"""
ratchet_demo.py - see the Double Ratchet and the post-quantum handshake at work
================================================================================
Runs alice and bob in ONE process (no server needed) and prints:
    1. the handshake suite and the size of each key-exchange field
    2. a different key for every single message
    3. a new ratchet key every time the conversation changes direction
    4. what an attacker gets from ONE leaked message key: exactly one message

Run:   python -m demos.ratchet_demo
"""

import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client.session import Session
from common.packet import V2_HEADER_SIZE, V2_PREFIX_SIZE
from common.ratchet import kdf_chain, message_cipher


def short(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def line(title=""):
    print(f"\n=== {title} " + "=" * max(0, 70 - len(title)))


def main():
    # ------------------------------------------------------------------ 1
    line("1. Handshake")
    alice = Session("bob", is_initiator=True)
    bob = Session("alice", is_initiator=False)
    init = alice.init_fields()
    resp = bob.respond(init)
    alice.finish(resp)
    print(f"Suite: {alice.suite}")
    for message, fields in (("KEY_INIT", init), ("KEY_RESP", resp)):
        for name, value in fields.items():
            print(f"  {message}  {name:8s} {len(value):5d} bytes")
    print("Both sides now share a root key, but neither ever sent it.")

    # ------------------------------------------------------------------ 2 + 3
    line("2+3. A new key for every message, a new ratchet key per direction change")
    script = [("alice", "Hi Bob"), ("alice", "Are you there?"), ("bob", "Yes!"),
              ("alice", "pay 100 to bob"), ("bob", "Thanks"), ("bob", "Got it")]
    captured = []   # what a network sniffer would record
    for speaker, text in script:
        sender, receiver = (alice, bob) if speaker == "alice" else (bob, alice)
        chain_before = sender.ratchet.send_chain
        _, message_key = kdf_chain(chain_before)          # the key this message will use
        packet = sender.encrypt_message(text)
        assert receiver.decrypt_message(packet) == text
        captured.append((speaker, text, packet, message_key))
        print(f"{speaker:5s} -> {text!r:20s} message key {short(message_key)}   "
              f"ratchet key {short(sender.ratchet.dh_self_public)}")

    # ------------------------------------------------------------------ 4
    line("4. Attacker leaks ONE message key (message #4)")
    leaked_index = 3
    _speaker, _text, _packet, leaked_key = captured[leaked_index]
    for i, (speaker, text, packet, _real_key) in enumerate(captured):
        prefix, header = packet[:V2_PREFIX_SIZE], packet[V2_PREFIX_SIZE:V2_HEADER_SIZE]
        key, nonce = message_cipher(leaked_key)
        try:
            plain = AESGCM(key).decrypt(nonce, packet[V2_HEADER_SIZE:], prefix + header).decode()
            result = f"DECRYPTED: {plain!r}"
        except Exception:
            result = "cannot decrypt"
        print(f"  message #{i + 1} ({speaker}): {result}")
    print("\nOne leaked key = one message. With Phase 2's single session key,")
    print("the same leak would have exposed all 6 messages.")


if __name__ == "__main__":
    main()
