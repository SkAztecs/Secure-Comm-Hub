"""
Phase 2 tests: identity keys, login, rate limiting, TLS, signed handshake,
trust-on-first-use, rekeying, tag-failure limit, security log, firewall hook.
"""

import asyncio
import os

import pytest

from client.identity import Identity, IdentityError, KnownPeers
from client.session import Session
from common import crypto_utils, tls
from common.handshake import init_transcript
from scripts.make_certs import make_certs
from server.auth import AuthError, LoginRateLimiter, UserStore
from tests.helpers import (PASSPHRASE, PASSWORD, connect, make_client, nothing_arrives,
                           read_events, start_relay)


# ---------------------------------------------------------------- identity at rest
def test_identity_saved_encrypted_and_reloaded(tmp_path):
    first = Identity.load_or_create("alice", PASSPHRASE, str(tmp_path))
    again = Identity.load_or_create("alice", PASSPHRASE, str(tmp_path))
    assert first.public_bytes == again.public_bytes

    # The private key must not be stored in plain text.
    raw = crypto_utils.identity_private_to_bytes(first._private_key).hex()
    with open(tmp_path / "alice" / "identity.json") as f:
        assert raw not in f.read()


def test_wrong_passphrase_is_refused(tmp_path):
    Identity.load_or_create("alice", PASSPHRASE, str(tmp_path))
    with pytest.raises(IdentityError):
        Identity.load_or_create("alice", "wrong passphrase", str(tmp_path))


def test_safety_number_is_symmetric_and_formatted():
    _, a = crypto_utils.generate_identity_keypair()
    _, b = crypto_utils.generate_identity_keypair()
    number = crypto_utils.safety_number(a, b)
    assert number == crypto_utils.safety_number(b, a)
    assert len(number.split()) == 6 and all(len(g) == 5 for g in number.split())


def test_signature_covers_names():
    identity_key, identity_pub = crypto_utils.generate_identity_keypair()
    eph = os.urandom(32)
    sig = crypto_utils.sign(identity_key, init_transcript("alice", "bob", eph))
    assert crypto_utils.verify_signature(identity_pub, sig, init_transcript("alice", "bob", eph))
    # Same signature can't be reused for a different responder.
    assert not crypto_utils.verify_signature(identity_pub, sig, init_transcript("alice", "carol", eph))


def test_known_peers_tofu(tmp_path):
    peers = KnownPeers("alice", str(tmp_path))
    assert peers.check("bob", b"1" * 32) == "new"
    assert peers.check("bob", b"1" * 32) == "match"
    assert peers.check("bob", b"2" * 32) == "changed"


# ---------------------------------------------------------------- accounts
def test_register_login_and_generic_errors():
    store = UserStore(":memory:")
    store.register("alice", PASSWORD, "aa" * 32)
    store.login("alice", PASSWORD, "aa" * 32)  # no exception = success

    with pytest.raises(AuthError, match="Invalid username or password"):
        store.login("alice", "wrong password", "aa" * 32)
    with pytest.raises(AuthError, match="Invalid username or password"):
        store.login("nobody", PASSWORD, "aa" * 32)
    with pytest.raises(AuthError, match="Identity key"):
        store.login("alice", PASSWORD, "bb" * 32)
    with pytest.raises(AuthError):
        store.register("alice", PASSWORD, "aa" * 32)  # duplicate


def test_password_is_hashed_not_stored():
    store = UserStore(":memory:")
    store.register("alice", PASSWORD, "aa" * 32)
    stored = store.db.execute("SELECT pw_hash FROM users").fetchone()[0]
    assert PASSWORD not in stored and stored.startswith("$argon2id$")


def test_rate_limiter_locks_after_five_failures():
    limiter = LoginRateLimiter()
    results = [limiter.record_failure("10.0.0.5") for _ in range(5)]
    assert results == [False, False, False, False, True]
    assert limiter.is_locked("10.0.0.5")
    assert not limiter.is_locked("10.0.0.6")


def test_brute_force_over_network_gets_locked_out_and_logged(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        victim = make_client(str(tmp_path), "alice")
        await connect(victim, relay)          # real account exists
        await victim.close()

        errors = []
        for _ in range(6):
            attacker = make_client(str(tmp_path), "alice")
            try:
                await connect(attacker, relay, register=False, password="guess-123")
            except ConnectionError as error:
                errors.append(str(error))
        await relay.stop()
        return errors

    errors = asyncio.run(scenario())
    assert "Invalid username or password" in errors[0]
    assert "Too many failed logins" in errors[-1]
    events = read_events(tmp_path / "server-security.jsonl")
    assert events.count("LOGIN_FAIL") >= 5 and "LOGIN_LOCKOUT" in events


# ---------------------------------------------------------------- TLS
def test_chat_over_tls_and_plain_client_is_rejected(tmp_path):
    cert_dir = str(tmp_path / "certs")
    make_certs(cert_dir)
    server_ctx = tls.server_context(f"{cert_dir}/server.pem", f"{cert_dir}/server.key")
    client_ctx = tls.client_context(f"{cert_dir}/ca.pem")

    async def scenario():
        relay = await start_relay(str(tmp_path), ssl_context=server_ctx)
        inbox = asyncio.Queue()
        alice = make_client(str(tmp_path), "alice")
        bob = make_client(str(tmp_path), "bob", inbox)
        await connect(alice, relay, ssl_context=client_ctx)
        await connect(bob, relay, ssl_context=client_ctx)
        tls_version = alice.writer.get_extra_info("ssl_object").version()

        await alice.start_chat("bob")
        await alice.send_chat("bob", "over tls")
        got = await asyncio.wait_for(inbox.get(), 5)

        # A client that does not speak TLS can't log in.
        plain = make_client(str(tmp_path), "carol")
        try:
            await asyncio.wait_for(connect(plain, relay), 5)
            plain_ok = True
        except (ConnectionError, asyncio.TimeoutError):
            plain_ok = False

        for c in (alice, bob, plain):
            await c.close()
        await relay.stop()
        return got, tls_version, plain_ok

    got, version, plain_ok = asyncio.run(scenario())
    assert got == ("alice", "over tls")
    assert version == "TLSv1.3"
    assert not plain_ok


# ---------------------------------------------------------------- identity change (TOFU)
def test_changed_identity_is_refused_until_trusted(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        bob_infos = []
        alice = make_client(str(tmp_path), "alice")
        bob = make_client(str(tmp_path), "bob", infos=bob_infos)
        await connect(alice, relay)
        await connect(bob, relay)
        await alice.start_chat("bob")            # bob saves alice's key (first use)
        await alice.close()

        # "alice" comes back with a DIFFERENT identity key (e.g. an impostor).
        relay.users.db.execute("DELETE FROM users WHERE username='alice'")
        _, other_pub = crypto_utils.generate_identity_keypair()
        impostor = make_client(str(tmp_path / "other"), "alice")
        await connect(impostor, relay)
        try:
            await impostor.start_chat("bob")
            refused = False
        except ConnectionError:
            refused = True

        # bob checks, then explicitly trusts the new key -> works again.
        trusted = bob.trust_new_key("alice")
        await impostor.start_chat("bob")

        for c in (impostor, bob):
            await c.close()
        await relay.stop()
        return refused, trusted, bob_infos

    import client.client_core as core
    old_timeout = core.HANDSHAKE_TIMEOUT
    core.HANDSHAKE_TIMEOUT = 1  # don't wait 10 s in a test
    try:
        refused, trusted, infos = asyncio.run(scenario())
    finally:
        core.HANDSHAKE_TIMEOUT = old_timeout

    assert refused and trusted
    assert any("CHANGED" in i for i in infos)
    assert "IDENTITY_CHANGED" in read_events(tmp_path / "security-bob.jsonl")


# ---------------------------------------------------------------- rekey + tag fails
def test_automatic_rekey_keeps_chat_working(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        inbox = asyncio.Queue()
        alice = make_client(str(tmp_path), "alice")
        bob = make_client(str(tmp_path), "bob", inbox)
        await connect(alice, relay)
        await connect(bob, relay)
        await alice.start_chat("bob")
        first_keys = alice.sessions["bob"].send_key

        Session.MAX_MESSAGES = 3
        try:
            for i in range(7):
                await alice.send_chat("bob", f"m{i}")
            received = [(await asyncio.wait_for(inbox.get(), 5))[1] for _ in range(7)]
        finally:
            Session.MAX_MESSAGES = 1000
        new_keys = alice.sessions["bob"].send_key

        await alice.close()
        await bob.close()
        await relay.stop()
        return received, first_keys != new_keys

    received, changed = asyncio.run(scenario())
    assert received == [f"m{i}" for i in range(7)]
    assert changed


def test_three_tag_failures_close_the_session(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        alice = make_client(str(tmp_path), "alice")
        bob = make_client(str(tmp_path), "bob")
        await connect(alice, relay)
        await connect(bob, relay)
        await alice.start_chat("bob")

        # Tamper with 3 packets on the way: flip the last ciphertext byte.
        original_route = relay.route

        async def tampering_route(sender, envelope):
            if envelope.get("type") == "CHAT":
                from common.envelope import b64decode, b64encode
                packet = bytearray(b64decode(envelope["packet"]))
                packet[-1] ^= 0x01
                envelope["packet"] = b64encode(bytes(packet))
            await original_route(sender, envelope)
        relay.route = tampering_route

        for i in range(3):
            await alice.send_chat("bob", f"msg {i}")
        await asyncio.sleep(0.3)
        closed = "alice" not in bob.sessions

        await alice.close()
        await bob.close()
        await relay.stop()
        return closed

    assert asyncio.run(scenario())
    events = read_events(tmp_path / "security-bob.jsonl")
    assert events.count("TAG_FAIL") == 3 and "SESSION_CLOSED_TAG_FAILS" in events


# ---------------------------------------------------------------- firewall hook
def test_blacklisted_ip_is_dropped_before_login(tmp_path):
    async def scenario():
        relay = await start_relay(str(tmp_path))
        with open(tmp_path / "blacklist.txt", "w") as f:
            f.write("# written by Pillar 3\n127.0.0.1\n")
        alice = make_client(str(tmp_path), "alice")
        try:
            await asyncio.wait_for(connect(alice, relay), 5)
            ok = True
        except (ConnectionError, asyncio.TimeoutError):
            ok = False
        await relay.stop()
        return ok

    assert not asyncio.run(scenario())
    assert "BLOCKED_CONNECTION" in read_events(tmp_path / "server-security.jsonl")


# ---------------------------------------------------------------- insecure demo mode
def test_insecure_mode_is_malleable_secure_mode_is_not():
    key = b"k" * 32
    from common.packet import build_packet, open_packet
    from common.message_types import CHAT
    from cryptography.exceptions import InvalidTag

    # Insecure (AES-CTR): flipping bits turns "pay 100" into "pay 900" silently.
    packet = bytearray(build_packet(CHAT, 0, key, b"pay 100", insecure=True))
    packet[22 + 4] ^= ord("1") ^ ord("9")    # 22 = header(10) + nonce(12); 4 = position of '1'
    assert open_packet(key, bytes(packet), insecure=True)[2] == b"pay 900"

    # Secure (AES-GCM): the same flip is detected.
    packet = bytearray(build_packet(CHAT, 0, key, b"pay 100"))
    packet[22 + 4] ^= ord("1") ^ ord("9")
    with pytest.raises(InvalidTag):
        open_packet(key, bytes(packet))
