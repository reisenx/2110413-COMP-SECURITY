import re
import ssl
import socket
import sys

import pem
from OpenSSL import crypto

CA_FILE = "./ca-certificates.crt"
HOSTS = [
    "twitter.com",
    "google.com",
    "www.chula.ac.th",
    "classdeedee.cloud.cp.eng.chula.ac.th",
]
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n", re.S)


def fetch_chain(host, port=443):
    """Ask the server for its certificates with `openssl s_client -showcerts`.
    Returns [leaf, intermediate1, ...] as PEM strings."""
    import subprocess

    out = subprocess.run(
        [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:{port}",
            "-servername",
            host,
            "-showcerts",
        ],
        input="",
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    return PEM_RE.findall(out)


def verify_chain_of_trust(cert_pem, trusted_cert_pems):
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    # Create and fill a X509Store with trusted certs
    store = crypto.X509Store()
    for trusted_cert_pem in trusted_cert_pems:
        trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
        store.add_cert(trusted_cert)

    # Create a X509StoreContext with the cert and trusted certs and verify the chain of trust
    store_ctx = crypto.X509StoreContext(store, certificate)
    try:
        store_ctx.verify_certificate()  # returns None if the certificate can be validated
        return True, "ok"
    except crypto.X509StoreContextError as e:
        return False, str(e)


def verify(host, use_intermediate=True):
    chain = fetch_chain(host)
    cert, int_certs = chain[0], chain[1:]

    pems = pem.parse_file(CA_FILE)
    trusted_certs = [str(p) for p in pems]
    if use_intermediate:
        trusted_certs.extend(int_certs)

    return verify_chain_of_trust(cert, trusted_certs)


if __name__ == "__main__":
    for host in sys.argv[1:] or HOSTS:
        for use_int in (False, True):
            try:
                ok, msg = verify(host, use_int)
            except Exception as e:  # network / parse problems
                ok, msg = False, f"{type(e).__name__}: {e}"
            label = "with intermediate" if use_int else "root store only "
            print(
                f"{host:40s} [{label}] ->",
                "Certificate verified" if ok else f"FAILED ({msg})",
            )
