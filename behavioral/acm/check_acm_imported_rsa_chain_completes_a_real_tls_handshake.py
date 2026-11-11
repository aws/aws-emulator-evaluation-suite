"""acm-imported-rsa-chain-completes-a-real-tls-handshake."""
from __future__ import annotations

import datetime
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-imported-rsa-chain-completes-a-real-tls-handshake"
GROUP = 'data-plane'
SERVICES = ['acm']

# ===== helpers (self-contained) =====
# Certificate minting, import, polling and throttle retry, plus a local TLS echo server/client.

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")


def _crypto():
    """Lazily import `cryptography`; ImportError propagates if it is absent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _subject(cn):
    """An X.509 Name. The CN is capped at 64 characters by RFC 5280 / `cryptography`."""
    x509, _h, _s, _r, NameOID = _crypto()
    assert len(cn) <= 64, f"CN {cn!r} is {len(cn)} chars; X.509 caps it at 64"
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-probe-acm-not-a-real-key"),
    ])


def _pem(cert):
    _x, _h, serialization, _r, _n = _crypto()
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key):
    """PEM-serialise a key generated moments ago in this process. It is not a credential."""
    _x, _h, serialization, _r, _n = _crypto()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _rsa_key():
    _x, _h, _s, rsa, _n = _crypto()
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _root_ca(cn):
    """A self-signed RSA-2048 CA, usable as a client trust anchor."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn))
        .issuer_name(_subject(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(cn, sans, issuer_cn, issuer_key):
    """A server certificate signed by `issuer_key`, with a DNS SAN list."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn))
        .issuer_name(_subject(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def _import(ctx, acm, cert_pem, key_pem, **kwargs):
    """ImportCertificate + teardown registered at creation time. Returns the ARN."""
    resp = _retry_throttle(lambda: acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0))
    return arn


def _tls_echo_server(server_pem, key_pem, tmpdir):
    """One-shot TLS echo server on 127.0.0.1, serving exactly `server_pem`.

    Returns (port, stop, box). `box` collects the server side's own view so a handshake the
    client rejects can still be attributed.
    """
    chain_path = os.path.join(tmpdir, "server-chain.pem")
    key_path = os.path.join(tmpdir, "server-key.pem")
    with open(chain_path, "wb") as fh:
        fh.write(server_pem)
    with open(key_path, "wb") as fh:
        fh.write(key_pem)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(chain_path, key_path)
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    lsock.settimeout(60)
    port = lsock.getsockname()[1]
    box: dict[str, str] = {}

    def _serve():
        try:
            raw, _peer = lsock.accept()
            raw.settimeout(30)
            with sctx.wrap_socket(raw, server_side=True) as tls:
                box["server_version"] = tls.version() or ""
                payload = tls.recv(4096)
                tls.sendall(payload)
        except OSError as exc:  # TLS and socket failures are reported, never raised into the check
            box["server_error"] = f"{type(exc).__name__}: {exc}"

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    def _stop():
        try:
            lsock.close()
        except OSError:
            pass
        thread.join(timeout=65)

    return port, _stop, box


def _tls_connect(port, trust_pem, hostname, nonce, tmpdir, label):
    """Connect to 127.0.0.1:port trusting ONLY `trust_pem`, with hostname verification on.

    `server_hostname` drives both SNI and the certificate hostname check, so the SAN is
    verified even though the connection is to a loopback address.
    """
    trust_path = os.path.join(tmpdir, f"trust-{label}.pem")
    with open(trust_path, "wb") as fh:
        fh.write(trust_pem)
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.load_verify_locations(cafile=trust_path)
    cctx.check_hostname = True
    cctx.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection(("127.0.0.1", port), timeout=30) as raw:
        with cctx.wrap_socket(raw, server_hostname=hostname) as tls:
            tls.sendall(nonce)
            echoed = b""
            while len(echoed) < len(nonce):
                chunk = tls.recv(len(nonce) - len(echoed))
                if not chunk:
                    break
                echoed += chunk
            return {
                "version": tls.version(),
                "cipher": tls.cipher(),
                "peer": tls.getpeercert(),
                "peer_der": tls.getpeercert(binary_form=True),
                "echo": echoed,
            }


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """The PEM chain ACM returns for an imported RSA certificate is byte-identical to what was
    imported and terminates a real TLS 1.3 handshake with hostname verification, presenting the
    locally generated leaf, so the stored chain is usable and not just echoed."""
    acm = ctx.client("acm")
    uid = ctx.unique_name("sim2real-behav-rsa-")
    host = f"{uid}.example.com"
    nonce = f"sim2real-nonce-{uid}".encode()

    root, root_key = _root_ca(f"root-{uid}")
    leaf, leaf_key = _leaf(host, [host], f"root-{uid}", root_key)

    arn = _import(ctx, acm, _pem(leaf), _key_pem(leaf_key), CertificateChain=_pem(root))
    detail = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED",
        timeout_s=120, interval_s=3,
        description="imported RSA certificate reaches ISSUED",
    )
    assert detail["KeyAlgorithm"] == "RSA-2048", (
        f"KeyAlgorithm must be parsed from the imported key; got {detail['KeyAlgorithm']!r}"
    )

    got = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))
    served_leaf = got["Certificate"]
    served_chain = got.get("CertificateChain") or ""

    # (1) ACM re-serves OUR leaf bytes, not a re-encoding.
    assert served_leaf.strip() == _pem(leaf).decode().strip(), (
        "GetCertificate must return the imported leaf PEM unchanged; got "
        f"{served_leaf[:60]!r}... vs imported {_pem(leaf).decode()[:60]!r}..."
    )
    # (2) The chain field carries the one CA certificate that was imported with it.
    assert served_chain.count("BEGIN CERTIFICATE") == 1, (
        "a 2-level import supplies exactly one CA certificate, so CertificateChain must hold "
        f"exactly one; got {served_chain.count('BEGIN CERTIFICATE')}"
    )

    tmpdir = tempfile.mkdtemp(prefix="sim2real-acm-rsa-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))

    # The server is built ONLY from what ACM returned; the private key never left this process.
    server_pem = served_leaf.encode() + b"\n" + served_chain.encode()
    port, stop, box = _tls_echo_server(server_pem, _key_pem(leaf_key), tmpdir)
    ctx.on_cleanup(stop)
    result = _tls_connect(port, _pem(root), host, nonce, tmpdir, "root")

    # (3) The handshake really completed, at the version the host's OpenSSL negotiates.
    assert result["version"] == "TLSv1.3", (
        f"handshake negotiated {result['version']!r}, expected 'TLSv1.3' "
        f"(server side saw {box.get('server_version')!r}, error {box.get('server_error')!r})"
    )
    # (4) The tunnel carried data both ways -- not just a handshake that then died.
    assert result["echo"] == nonce, (
        f"the TLS tunnel echoed {result['echo']!r}, expected {nonce!r} "
        f"(server error {box.get('server_error')!r})"
    )
    # (5) Hostname verification passed against the SAN parsed out of ACM's bytes.
    sans = [v for typ, v in (result["peer"].get("subjectAltName") or ()) if typ == "DNS"]
    assert sans == [host], (
        f"the presented certificate's DNS SANs were {sans!r}, expected exactly [{host!r}]"
    )
    # (6) It is OUR certificate, identified by serial -- ACM did not substitute one.
    presented_serial = int(result["peer"]["serialNumber"], 16)
    assert presented_serial == leaf.serial_number, (
        f"the certificate served over TLS has serial {presented_serial:x}, but the imported "
        f"leaf's serial is {leaf.serial_number:x} -- ACM returned a different certificate"
    )
    # (7) And the DER on the wire is the DER we generated, byte for byte.
    x509m, _h, serialization, _r, _n = _crypto()
    wire_der = result["peer_der"]
    local_der = leaf.public_bytes(serialization.Encoding.DER)
    assert wire_der == local_der, (
        f"the DER presented over TLS is {len(wire_der)} bytes and the imported DER is "
        f"{len(local_der)} bytes; they must be identical"
    )
    assert x509m.load_der_x509_certificate(wire_der).subject == leaf.subject, (
        "the presented certificate's subject must parse back to the imported subject; got "
        f"{x509m.load_der_x509_certificate(wire_der).subject.rfc4514_string()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
