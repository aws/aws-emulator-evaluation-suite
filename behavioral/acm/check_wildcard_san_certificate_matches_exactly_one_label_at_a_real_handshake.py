"""wildcard-san-certificate-matches-exactly-one-label-at-a-real-handshake."""
from __future__ import annotations

import datetime
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wildcard-san-certificate-matches-exactly-one-label-at-a-real-handshake"
GROUP = "data-plane"
SERVICES = ["acm"]

# ===== helpers (self-contained) =====

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


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on deadline (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _crypto():
    """Lazily import `cryptography`; a missing package raises ImportError to the runner."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _subject(cn):
    x509, _h, _s, _r, NameOID = _crypto()
    assert len(cn) <= 64, f"CN {cn!r} is {len(cn)} chars; X.509 caps it at 64"
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-acm-not-a-real-key"),
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
    """A self-signed RSA-2048 CA, used here as the client's ONLY trust anchor."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn)).issuer_name(_subject(cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
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
    """A server certificate signed by `issuer_key`, carrying exactly `sans` as DNS names."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn)).issuer_name(_subject(issuer_cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def _tls_echo_server(server_pem, key_pem, tmpdir, *, connections):
    """A TLS echo server on 127.0.0.1 serving exactly `server_pem`, for `connections` accepts.

    Returns (port, stop, box). `box` collects the SERVER side's own view of each handshake, so a
    handshake the client rejects can still be attributed to a side. Multi-shot because this
    check makes three connections to the SAME certificate; a rejected handshake must not take
    the server down and hide the two that follow.
    """
    chain_path = os.path.join(tmpdir, "server-chain.pem")
    key_path = os.path.join(tmpdir, "server-key.pem")
    with open(chain_path, "wb") as handle:
        handle.write(server_pem)
    with open(key_path, "wb") as handle:
        handle.write(key_pem)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(chain_path, key_path)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(connections)
    listener.settimeout(90)
    port = listener.getsockname()[1]
    box = {"handshakes": [], "errors": []}

    def _serve():
        for _ in range(connections):
            try:
                raw, _peer = listener.accept()
            except OSError as exc:
                box["errors"].append(f"accept: {type(exc).__name__}: {exc}")
                return
            raw.settimeout(30)
            try:
                with server_ctx.wrap_socket(raw, server_side=True) as tls:
                    box["handshakes"].append(tls.version() or "")
                    payload = tls.recv(4096)
                    tls.sendall(payload)
            except OSError as exc:
                # A client that ABORTS after rejecting the certificate surfaces here. Recorded
                # for attribution, never raised into the check: the client side is what grades.
                box["errors"].append(f"handshake: {type(exc).__name__}: {exc}")

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    def _stop():
        try:
            listener.close()
        except OSError:
            pass
        thread.join(timeout=95)

    return port, _stop, box


def _client_context(trust_pem, tmpdir, label):
    """A verifying TLS client context that trusts ONLY `trust_pem`, hostname checking ON."""
    trust_path = os.path.join(tmpdir, f"trust-{label}.pem")
    with open(trust_path, "wb") as handle:
        handle.write(trust_pem)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cafile=trust_path)
    client_ctx.check_hostname = True
    client_ctx.verify_mode = ssl.CERT_REQUIRED
    return client_ctx


def _tls_connect(client_ctx, port, hostname, nonce):
    """Connect to 127.0.0.1:port with SNI and hostname verification set to `hostname`."""
    with socket.create_connection(("127.0.0.1", port), timeout=30) as raw:
        with client_ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            tls.sendall(nonce)
            echoed = b""
            while len(echoed) < len(nonce):
                chunk = tls.recv(len(nonce) - len(echoed))
                if not chunk:
                    break
                echoed += chunk
            return {
                "version": tls.version(),
                "peer": tls.getpeercert(),
                "peer_der": tls.getpeercert(binary_form=True),
                "echo": echoed,
            }


def _expect_hostname_rejection(client_ctx, port, hostname, nonce, box):
    """Attempt a verified handshake that MUST be refused, and return the verification failure.

    RAISES on unexpected success rather than returning a falsy sentinel: a sentinel would let
    an over-permissive certificate turn acceptance into a reason mismatch. Only
    ssl.SSLCertVerificationError is caught -- a refused connection or a timeout must NOT read as
    "the certificate correctly failed to match".
    """
    try:
        _tls_connect(client_ctx, port, hostname, nonce)
    except ssl.SSLCertVerificationError as exc:
        return {"reason": exc.reason or "", "verify_code": exc.verify_code,
                "message": str(exc)}
    raise AssertionError(
        f"a certificate whose only SAN is a single-label wildcard must NOT verify for "
        f"{hostname!r}, but the handshake completed and was accepted "
        f"(server side saw {box['handshakes']!r}, errors {box['errors']!r})"
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A wildcard-only SAN (`*.<parent>`) imported into ACM behaves as a wildcard at a real TLS
    handshake built from the bytes GetCertificate returns: it verifies for exactly one label under
    the parent and is refused (hostname mismatch) for two labels and the bare parent (RFC 6125)."""
    acm = ctx.client("acm")

    uid = ctx.unique_name("sim2real-acm-wc-")
    parent = f"{uid}.example.com"
    wildcard = f"*.{parent}"
    one_label = f"host.{parent}"
    two_labels = f"deep.host.{parent}"
    nonce = f"sim2real-wildcard-{uid}".encode()

    root, root_key = _root_ca(f"root-{uid}")
    # The leaf's ONLY name is the wildcard: no apex SAN, so "matches the bare parent" cannot
    # succeed for the wrong reason.
    leaf, leaf_key = _leaf(wildcard, [wildcard], f"root-{uid}", root_key)

    arn = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf), PrivateKey=_key_pem(leaf_key), CertificateChain=_pem(root),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]

    def _delete():
        try:
            acm.delete_certificate(CertificateArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)

    detail = _poll_until(
        lambda: _retry_throttle(
            lambda: acm.describe_certificate(CertificateArn=arn))["Certificate"],
        lambda d: d["Status"] == "ISSUED",
        timeout_s=120, interval_s=3,
        description="the imported wildcard certificate reaching ISSUED",
    )

    # (1) ACM accepted a wildcard-only certificate and named it by the wildcard, verbatim.
    assert detail["DomainName"] == wildcard, (
        f"DomainName is parsed from the DER, so it must be the wildcard verbatim; ACM reports "
        f"{detail['DomainName']!r}, expected {wildcard!r}"
    )
    # (2) The `*` label survived the round trip -- unnormalised, unexpanded, not stripped.
    assert detail["SubjectAlternativeNames"] == [wildcard], (
        f"SubjectAlternativeNames must be exactly the one wildcard DNS name that the imported "
        f"DER carries; ACM reports {detail['SubjectAlternativeNames']!r}, expected "
        f"{[wildcard]!r}"
    )

    served = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))
    served_leaf = served["Certificate"]
    served_chain = served["CertificateChain"]
    assert served_leaf.strip() == _pem(leaf).decode().strip(), (
        f"GetCertificate must return the imported leaf PEM unchanged; got "
        f"{served_leaf[:60]!r}... vs imported {_pem(leaf).decode()[:60]!r}..."
    )
    assert served_chain.count("BEGIN CERTIFICATE") == 1, (
        f"a 2-level import supplies one CA certificate, so CertificateChain must hold exactly "
        f"one; got {served_chain.count('BEGIN CERTIFICATE')}"
    )

    tmpdir = tempfile.mkdtemp(prefix="sim2real-acm-wildcard-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    server_pem = served_leaf.encode() + b"\n" + served_chain.encode()
    port, stop, box = _tls_echo_server(server_pem, _key_pem(leaf_key), tmpdir, connections=3)
    ctx.on_cleanup(stop)
    client_ctx = _client_context(_pem(root), tmpdir, "root")

    # (3) POSITIVE CONTROL, and the leg that makes the two refusals attributable: exactly one
    #     label under the parent verifies, and the tunnel carries data both ways.
    result = _tls_connect(client_ctx, port, one_label, nonce)
    assert result["echo"] == nonce, (
        f"the TLS tunnel for {one_label!r} echoed {result['echo']!r}, expected {nonce!r} "
        f"(server side saw {box['handshakes']!r}, errors {box['errors']!r})"
    )
    # (4) Hostname verification passed against the wildcard SAN parsed out of ACM's bytes.
    sans = [value for kind, value in result["peer"]["subjectAltName"] if kind == "DNS"]
    assert sans == [wildcard], (
        f"the presented certificate's DNS SANs were {sans!r}, expected exactly {[wildcard]!r}"
    )
    # (5) And the DER on the wire is the DER that was imported, byte for byte.
    _x509m, _h, serialization, _r, _n = _crypto()
    local_der = leaf.public_bytes(serialization.Encoding.DER)
    assert result["peer_der"] == local_der, (
        f"the DER presented over TLS is {len(result['peer_der'])} bytes and the DER imported "
        f"into ACM is {len(local_der)} bytes; they must be identical"
    )

    # (6) The bare parent is NOT covered by `*.parent` (RFC 6125): refused, specifically.
    #     `.reason` is the generic "CERTIFICATE_VERIFY_FAILED" on this host's OpenSSL (hostname
    #     checking is folded into chain verification), so the specific signal is the OpenSSL
    #     verify code for a hostname mismatch, not the reason string.
    bare = _expect_hostname_rejection(client_ctx, port, parent, nonce, box)
    assert bare["verify_code"] == 62, (
        f"the refusal for the bare parent {parent!r} must carry OpenSSL's "
        f"X509_V_ERR_HOSTNAME_MISMATCH verify code (62), which chain and expiry failures do "
        f"not produce; ssl reported verify_code={bare['verify_code']!r} reason={bare['reason']!r} "
        f"({bare['message'][:160]})"
    )
    assert "Hostname mismatch" in bare["message"], (
        f"the verify-code-62 message must contain OpenSSL's literal 'Hostname mismatch' text; "
        f"message was {bare['message'][:200]!r}"
    )
    assert parent in bare["message"], (
        f"the verification failure must name the hostname it rejected ({parent!r}) -- that is "
        f"what separates a name mismatch from a chain failure; message was "
        f"{bare['message'][:200]!r}"
    )

    # (7) Two labels are NOT covered by a single-label wildcard: refused, specifically.
    deep = _expect_hostname_rejection(client_ctx, port, two_labels, nonce, box)
    assert deep["verify_code"] == 62, (
        f"the refusal for {two_labels!r} must carry OpenSSL's X509_V_ERR_HOSTNAME_MISMATCH "
        f"verify code (62); ssl reported verify_code={deep['verify_code']!r} "
        f"reason={deep['reason']!r} ({deep['message'][:160]})"
    )
    assert "Hostname mismatch" in deep["message"], (
        f"the verify-code-62 message must contain OpenSSL's literal 'Hostname mismatch' text; "
        f"message was {deep['message'][:200]!r}"
    )
    assert two_labels in deep["message"], (
        f"the verification failure must name the hostname it rejected ({two_labels!r}); "
        f"message was {deep['message'][:200]!r}"
    )

    # (8) Terminal read at ACM, through a DIFFERENT operation than the import and than
    #     DescribeCertificate: the server-side listing index also carries the wildcard name.
    #     ListCertificates is NOT synchronously consistent with
    #     ImportCertificate -- a freshly imported certificate can be absent for seconds even
    #     though DescribeCertificate/GetCertificate already see it ISSUED, so this leg
    #     polls with a stated bound rather than reading once right after the import.
    def _list_summaries():
        page_summaries = {}
        for page in acm.get_paginator("list_certificates").paginate():
            for summary in page["CertificateSummaryList"]:
                page_summaries[summary["CertificateArn"]] = summary
        return page_summaries

    summaries = _poll_until(
        _list_summaries, lambda s: arn in s,
        timeout_s=60, interval_s=3,
        description="the imported wildcard certificate appearing in ListCertificates",
    )
    assert summaries[arn]["DomainName"] == wildcard, (
        f"ListCertificates must index the wildcard name verbatim; got "
        f"{summaries[arn]['DomainName']!r}, expected {wildcard!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
