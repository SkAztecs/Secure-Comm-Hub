"""
tls.py
------
TLS 1.3 settings for both sides, in one place.

Why TLS if messages are already end-to-end encrypted?  Defence in depth:
    - E2E (AES-GCM between clients) hides message CONTENT, even from the server.
    - TLS (client <-> server) hides everything else on the network: usernames,
      who talks to whom, the login password, message sizes per type.
"""

import ssl


def server_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """TLS context for the relay server."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3  # refuse TLS 1.2 and older
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def client_context(ca_file: str) -> ssl.SSLContext:
    """
    TLS context for clients. Trusts ONLY our project CA (not the system CAs),
    and checks that the certificate matches the host we connect to.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies cert + hostname by default
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=ca_file)
    return context
