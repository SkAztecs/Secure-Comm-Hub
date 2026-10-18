"""
tamper_attack.py - ATTACK 3: bit-flipping
------------------------------------------
Stream-cipher modes like AES-CTR are MALLEABLE: ciphertext = plaintext XOR keystream,
so flipping a ciphertext bit flips the SAME plaintext bit. If the attacker can guess
the message format, it can change it without knowing the key:

    "pay 100 to bob"  --flip byte 4 by ('1' XOR '9')-->  "pay 900 to bob"

    --insecure clients (AES-CTR, no tag) -> bob sees "pay 900 to bob", no warning
    secure clients (AES-GCM)              -> tag check fails -> TAG_FAIL, rejected
                                             (3 tampered messages close the session)

Run (server + clients with --no-tls, clients pointing at port 9100):
    python -m attacks.tamper_attack --listen 9100 --server-port 9000 --position 4 --from-char 1 --to-char 9
Then send exactly:  pay 100 to bob
"""

from attacks.proxy_base import RED, AttackProxy, common_args, run, say
from common.envelope import b64decode, b64encode

# Ciphertext starts after header (10 bytes) + nonce (12 bytes).
CIPHERTEXT_OFFSET = 22


class TamperProxy(AttackProxy):
    name = "TAMPER"

    def __init__(self, *args, position=4, from_char="1", to_char="9"):
        super().__init__(*args)
        self.position = position
        self.xor_value = ord(from_char) ^ ord(to_char)
        self.description = f"'{from_char}' -> '{to_char}' at character {position}"

    async def on_client_frame(self, conn, envelope):
        if envelope.get("type") == "CHAT":
            packet = bytearray(b64decode(envelope["packet"]))
            index = CIPHERTEXT_OFFSET + self.position
            if index < len(packet):
                packet[index] ^= self.xor_value
                envelope["packet"] = b64encode(bytes(packet))
                say(RED, f"[TAMPER] flipped bits in {conn.username} -> {envelope.get('to')} "
                         f"({self.description}) without knowing the key")
        return [envelope]


def main():
    parser = common_args("Bit-flipping attack proxy (demo only)")
    parser.add_argument("--position", type=int, default=4, help="character index to change")
    parser.add_argument("--from-char", default="1")
    parser.add_argument("--to-char", default="9")
    args = parser.parse_args()
    run(TamperProxy(args.listen, args.server_host, args.server_port,
                    position=args.position, from_char=args.from_char, to_char=args.to_char))


if __name__ == "__main__":
    main()
