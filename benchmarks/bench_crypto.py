"""
bench_crypto.py - Phase 3 performance numbers for the report
=============================================================
Measures what the security features COST:

    1. Handshake time        classic X25519   vs   X25519 + ML-KEM-768 (post-quantum hybrid)
    2. Per-message crypto    one static AES-GCM key (Phase 2)   vs   Double Ratchet (Phase 3)
                             for 64 B, 1 KB and 32 KB messages
    3. Round-trip latency    through a real relay on this machine: no TLS vs TLS 1.3
    4. File throughput       5 MB file through the relay with TLS
    5. Size on the wire      handshake bytes and per-message overhead

Results go to benchmarks/results/:
    results.csv, results.md (table for the report) and PNG charts (if matplotlib is installed).

Run (from the project folder):
    python -m benchmarks.bench_crypto
Numbers depend on the machine - always say which laptop they came from in the report.
"""

import asyncio
import csv
import os
import platform
import statistics
import tempfile
import time

from client.session import Session
from common import crypto_utils
from common.handshake import init_transcript, resp_transcript

OUT_DIR = os.path.join("benchmarks", "results")

# Reference palette (dataviz skill): categorical slots 1 and 2, light surface.
BLUE, ORANGE = "#2a78d6", "#eb6834"
SURFACE, INK, INK_2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e5e4df"


def median_time(function, runs):
    """Run `function` `runs` times; return the median duration in seconds."""
    durations = []
    for _ in range(runs):
        start = time.perf_counter()
        function()
        durations.append(time.perf_counter() - start)
    return statistics.median(durations)


# ======================================================================
# 1. Handshake
# ======================================================================
def bench_handshake(pq, runs=200):
    alice_id, _ = crypto_utils.generate_identity_keypair()
    bob_id, _ = crypto_utils.generate_identity_keypair()
    alice_pub = alice_id.public_key().public_bytes_raw()
    bob_pub = bob_id.public_key().public_bytes_raw()

    def one_handshake():
        alice = Session("bob", is_initiator=True, pq=pq)
        bob = Session("alice", is_initiator=False, pq=pq)
        init = alice.init_fields()
        sig_a = alice_id.sign(init_transcript("alice", "bob", init))
        assert crypto_utils.verify_signature(alice_pub, sig_a, init_transcript("alice", "bob", init))
        resp = bob.respond(init)
        sig_b = bob_id.sign(resp_transcript("alice", "bob", init, resp))
        assert crypto_utils.verify_signature(bob_pub, sig_b, resp_transcript("alice", "bob", init, resp))
        alice.finish(resp)
        return init, resp

    init, resp = one_handshake()
    wire_bytes = sum(len(v) for v in init.values()) + sum(len(v) for v in resp.values()) + 2 * (32 + 64)
    return median_time(one_handshake, runs) * 1000, wire_bytes


# ======================================================================
# 2. Per-message crypto
# ======================================================================
def bench_static_gcm(size, runs):
    key, header, data = os.urandom(32), b"h" * 10, os.urandom(size)
    counter = [0]

    def roundtrip():
        counter[0] += 1
        ct = crypto_utils.encrypt(key, counter[0], header, data)
        crypto_utils.decrypt(key, counter[0], header, ct)
    return median_time(roundtrip, runs) * 1e6


def bench_ratchet(size, runs):
    alice = Session("bob", is_initiator=True)
    bob = Session("alice", is_initiator=False)
    alice.finish(bob.respond(alice.init_fields()))
    data = os.urandom(size)
    turn = [0]

    def roundtrip():
        # Change direction every 10 messages so DH ratchet steps are included.
        turn[0] += 1
        sender, receiver = (alice, bob) if (turn[0] // 10) % 2 == 0 else (bob, alice)
        receiver.decrypt_packet(sender.encrypt_message(data))
    return median_time(roundtrip, runs) * 1e6


# ======================================================================
# 3 + 4. Through a real relay
# ======================================================================
async def relay_benchmarks(use_tls, rtt_runs=100, file_mb=5):
    from scripts.make_certs import make_certs
    from tests.helpers import connect, make_client, start_relay
    from common import tls

    tmp = tempfile.mkdtemp(prefix="bench_")
    server_ctx = client_ctx = None
    if use_tls:
        make_certs(os.path.join(tmp, "certs"))
        server_ctx = tls.server_context(f"{tmp}/certs/server.pem", f"{tmp}/certs/server.key")
        client_ctx = tls.client_context(f"{tmp}/certs/ca.pem")

    relay = await start_relay(tmp, ssl_context=server_ctx)
    replies = asyncio.Queue()
    alice = make_client(tmp, "alice", inbox=replies)
    bob = make_client(tmp, "bob")
    bob.incoming_files.folder = os.path.join(tmp, "downloads")
    # bob echoes every message straight back
    bob.on_message = lambda peer, text: asyncio.ensure_future(bob.send_chat(peer, text))
    await connect(alice, relay, ssl_context=client_ctx)
    await connect(bob, relay, ssl_context=client_ctx)
    await alice.start_chat("bob")

    rtts = []
    for i in range(rtt_runs):
        start = time.perf_counter()
        await alice.send_chat("bob", f"ping {i}")
        await asyncio.wait_for(replies.get(), 5)
        rtts.append(time.perf_counter() - start)

    throughput = None
    if file_mb:
        path = os.path.join(tmp, "big.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(file_mb * 1024 * 1024))
        done = asyncio.Event()
        bob.on_info = lambda text: done.set() if text.startswith("Received file") else None
        start = time.perf_counter()
        await alice.send_file("bob", path)
        await asyncio.wait_for(done.wait(), 60)
        throughput = file_mb / (time.perf_counter() - start)

    await alice.close()
    await bob.close()
    await relay.stop()
    return statistics.median(rtts) * 1000, throughput


# ======================================================================
# Charts (optional)
# ======================================================================
def make_charts(results):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - skipping charts (pip install matplotlib)")
        return []

    plt.rcParams.update({"font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": INK_2,
                         "xtick.color": INK_2, "ytick.color": INK_2, "text.color": INK})
    paths = []

    def style(ax, title, xlabel):
        ax.set_facecolor(SURFACE)
        ax.set_title(title, loc="left", fontsize=11, fontweight="bold", color=INK)
        ax.set_xlabel(xlabel)
        ax.grid(axis="x", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)

    def save(fig, name):
        path = os.path.join(OUT_DIR, name)
        fig.patch.set_facecolor(SURFACE)
        fig.tight_layout()
        fig.savefig(path, dpi=160)
        plt.close(fig)
        paths.append(path)

    # --- Chart 1: handshake time (one measure, 2 items -> horizontal bars) ---
    fig, ax = plt.subplots(figsize=(6.4, 2.2))
    labels = ["X25519 (classic)", "X25519 + ML-KEM-768"]
    values = [results["handshake_classic_ms"], results["handshake_pq_ms"]]
    bars = ax.barh(labels, values, color=[BLUE, ORANGE], height=0.5)
    for bar, value in zip(bars, values):
        ax.text(bar.get_width(), bar.get_y() + bar.get_height() / 2, f"  {value:.2f} ms",
                va="center", color=INK, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, max(values) * 1.3)
    style(ax, "Post-quantum hybrid handshake cost (median, signed)", "milliseconds")
    save(fig, "handshake.png")

    # --- Chart 2: per-message cost, grouped by size (2 series -> legend + labels) ---
    sizes = ["64 B", "1 KB", "32 KB"]
    static = [results[f"msg_static_{s}_us"] for s in ("64", "1024", "32768")]
    ratchet = [results[f"msg_ratchet_{s}_us"] for s in ("64", "1024", "32768")]
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    y = range(len(sizes))
    h = 0.36
    b1 = ax.barh([i - h / 2 - 0.01 for i in y], static, height=h, color=BLUE,
                 label="Static AES-GCM key (Phase 2)")
    b2 = ax.barh([i + h / 2 + 0.01 for i in y], ratchet, height=h, color=ORANGE,
                 label="Double Ratchet (Phase 3)")
    for group in (b1, b2):
        for bar in group:
            ax.text(bar.get_width(), bar.get_y() + bar.get_height() / 2,
                    f"  {bar.get_width():.0f} µs", va="center", color=INK, fontsize=8.5)
    ax.set_yticks(list(y), sizes)
    ax.invert_yaxis()
    ax.set_xlim(0, max(static + ratchet) * 1.3)
    # Legend below the axis, so it can never cover a bar or a value label.
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.28), ncol=2, fontsize=8.5)
    style(ax, "Encrypt + decrypt one message (median)", "microseconds")
    save(fig, "message_cost.png")

    # --- Chart 3: round trip through the relay ---
    fig, ax = plt.subplots(figsize=(6.4, 2.2))
    labels = ["Plain TCP (demo)", "TLS 1.3"]
    values = [results["rtt_no_tls_ms"], results["rtt_tls_ms"]]
    bars = ax.barh(labels, values, color=[BLUE, ORANGE], height=0.5)
    for bar, value in zip(bars, values):
        ax.text(bar.get_width(), bar.get_y() + bar.get_height() / 2, f"  {value:.2f} ms",
                va="center", color=INK, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, max(values) * 1.3)
    style(ax, "Chat round trip via the relay, same machine (median)", "milliseconds")
    save(fig, "round_trip.png")
    return paths


# ======================================================================
def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    results = {}
    print("1/4 handshakes...")
    results["handshake_classic_ms"], results["handshake_classic_bytes"] = bench_handshake(pq=False)
    if crypto_utils.HAS_MLKEM:
        results["handshake_pq_ms"], results["handshake_pq_bytes"] = bench_handshake(pq=True)
    else:
        print("   ML-KEM unavailable (cryptography < 47) - skipping the post-quantum handshake")
        results["handshake_pq_ms"], results["handshake_pq_bytes"] = float("nan"), 0

    print("2/4 per-message crypto...")
    for size, runs in ((64, 3000), (1024, 3000), (32768, 1000)):
        results[f"msg_static_{size}_us"] = bench_static_gcm(size, runs)
        results[f"msg_ratchet_{size}_us"] = bench_ratchet(size, runs)

    print("3/4 relay round trips (no TLS, TLS)...")
    results["rtt_no_tls_ms"], _ = asyncio.run(relay_benchmarks(False, file_mb=0))
    print("4/4 relay round trips + 5 MB file over TLS...")
    results["rtt_tls_ms"], results["file_tls_mb_per_s"] = asyncio.run(relay_benchmarks(True))

    # Wire overhead of one encrypted chat message (v2 packet: 42-byte header + 16-byte tag).
    results["msg_overhead_bytes"] = 42 + 16

    machine = f"{platform.system()} {platform.release()}, {platform.processor() or platform.machine()}, Python {platform.python_version()}"
    with open(os.path.join(OUT_DIR, "results.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        for key, value in results.items():
            writer.writerow([key, f"{value:.4f}" if isinstance(value, float) else value])

    r = results
    table = f"""# Benchmark results

Machine: {machine}
All values are medians.

| Measurement | Classic / Phase 2 | Phase 3 | Change |
|---|---|---|---|
| Signed handshake time | {r['handshake_classic_ms']:.2f} ms (X25519) | {r['handshake_pq_ms']:.2f} ms (X25519 + ML-KEM-768) | +{r['handshake_pq_ms'] - r['handshake_classic_ms']:.2f} ms |
| Handshake bytes (keys + signatures) | {r['handshake_classic_bytes']:,} B | {r['handshake_pq_bytes']:,} B | +{r['handshake_pq_bytes'] - r['handshake_classic_bytes']:,} B |
| Encrypt + decrypt, 64 B message | {r['msg_static_64_us']:.0f} µs (static key) | {r['msg_ratchet_64_us']:.0f} µs (Double Ratchet) | ×{r['msg_ratchet_64_us'] / r['msg_static_64_us']:.1f} |
| Encrypt + decrypt, 1 KB message | {r['msg_static_1024_us']:.0f} µs | {r['msg_ratchet_1024_us']:.0f} µs | ×{r['msg_ratchet_1024_us'] / r['msg_static_1024_us']:.1f} |
| Encrypt + decrypt, 32 KB message | {r['msg_static_32768_us']:.0f} µs | {r['msg_ratchet_32768_us']:.0f} µs | ×{r['msg_ratchet_32768_us'] / r['msg_static_32768_us']:.1f} |

| Through the relay (same machine) | Value |
|---|---|
| Chat round trip, plain TCP | {r['rtt_no_tls_ms']:.2f} ms |
| Chat round trip, TLS 1.3 | {r['rtt_tls_ms']:.2f} ms |
| 5 MB file transfer over TLS | {r['file_tls_mb_per_s']:.1f} MB/s |
| Overhead per encrypted message | {r['msg_overhead_bytes']} B (42-byte header + 16-byte tag) |
"""
    with open(os.path.join(OUT_DIR, "results.md"), "w", encoding="utf-8") as f:
        f.write(table)
    print("\n" + table)

    for path in make_charts(results):
        print("chart:", path)


if __name__ == "__main__":
    main()
