"""
make_certs.py
-------------
Creates a tiny private Certificate Authority (CA) and a TLS certificate for the
relay server, using only the `cryptography` library (no OpenSSL install needed,
works the same on Windows, macOS and Linux).

Output (folder certs/):
    ca.pem        CA certificate  -> give this to every client (public, safe to share)
    ca.key        CA private key  -> keep secret (only needed to make new certs)
    server.pem    server certificate, signed by the CA
    server.key    server private key -> stays on the server machine only

The server certificate is valid for "localhost", 127.0.0.1 and every --ip you pass.
Clients connect using one of those names/IPs, otherwise TLS refuses (hostname check).

Usage:
    python scripts/make_certs.py --ip 172.17.177.67
    python scripts/make_certs.py --ip 172.17.177.67 --ip 192.168.1.20
"""

import argparse
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_key(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))


def write_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def make_certs(out_dir="certs", ips=(), dns_names=("localhost",), days=365):
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    # ---------------- 1. the CA ----------------
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Project CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # ---------------- 2. the server certificate ----------------
    server_key = ec.generate_private_key(ec.SECP256R1())
    alt_names = [x509.DNSName(name) for name in dns_names]
    unique_ips = dict.fromkeys(("127.0.0.1", *ips))  # keeps order, drops duplicates
    alt_names += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in unique_ips]

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Relay")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    write_key(os.path.join(out_dir, "ca.key"), ca_key)
    write_cert(os.path.join(out_dir, "ca.pem"), ca_cert)
    write_key(os.path.join(out_dir, "server.key"), server_key)
    write_cert(os.path.join(out_dir, "server.pem"), server_cert)
    return [str(n.value) for n in alt_names]


def main():
    parser = argparse.ArgumentParser(description="Create a private CA + server TLS certificate")
    parser.add_argument("--ip", action="append", default=[],
                        help="server IP clients will connect to (repeatable)")
    parser.add_argument("--dns", action="append", default=[], help="extra DNS name (repeatable)")
    parser.add_argument("--out", default="certs")
    args = parser.parse_args()

    names = make_certs(args.out, args.ip, ("localhost", *args.dns))
    print(f"Created {args.out}/ca.pem, ca.key, server.pem, server.key")
    print("Server certificate valid for:", ", ".join(names))
    print(f"Copy {args.out}/ca.pem to every client machine (same path). Keep the .key files private.")


if __name__ == "__main__":
    main()
