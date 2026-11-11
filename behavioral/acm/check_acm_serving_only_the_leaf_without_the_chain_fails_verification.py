"""acm-serving-only-the-leaf-without-the-chain-fails-verification."""
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

CHECK = "acm-serving-only-the-leaf-without-the-chain-fails-verification"
GROUP = 'data-plane'
SERVICES = ['acm']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes."""
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
    """Poll probe() until predicate(result) is truthy; raise on timeout."""
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


def _ca(cn, issuer_cn=None, issuer_key=None):
    """A CA certificate: self-signed when no issuer is given, otherwise signed by it."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn))
        .issuer_name(_subject(issuer_cn or cn))
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
        .sign(issuer_key or key, hashes.SHA256())
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


def _tls_echo_server(server_pem, key_pem, tmpdir, label):
    """One-shot TLS echo server on 127.0.0.1, serving exactly `server_pem`."""
    chain_path = os.path.join(tmpdir, f"server-chain-{label}.pem")
    key_path = os.path.join(tmpdir, f"server-key-{label}.pem")
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
                box["payload"] = payload
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
    """Connect to 127.0.0.1:port trusting ONLY `trust_pem`, with hostname verification on."""
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
            return {"version": tls.version(), "echo": echoed, "peer": tls.getpeercert()}


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """GetCertificate's CertificateChain is the required intermediate path: serving the leaf alone
    fails TLS path validation, while leaf + chain completes a handshake with the same client.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_GetCertificate.html
    """
    acm = ctx.client("acm")
    uid = ctx.unique_name("sim2real-behav-chain-")
    host = f"{uid}.example.com"
    nonce = f"sim2real-nonce-{uid}".encode()

    root, root_key = _ca(f"root-{uid}")
    inter, inter_key = _ca(f"inter-{uid}", issuer_cn=f"root-{uid}", issuer_key=root_key)
    leaf, leaf_key = _leaf(host, [host], f"inter-{uid}", inter_key)

    arn = _import(ctx, acm, _pem(leaf), _key_pem(leaf_key),
                  CertificateChain=_pem(inter) + _pem(root))
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED",
        timeout_s=120, interval_s=3,
        description="imported 3-level certificate reaches ISSUED",
    )

    got = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))
    served_leaf, served_chain = got["Certificate"], got.get("CertificateChain") or ""

    # (1) The chain field holds the intermediate AND the root, in the imported order. This is the
    #     structural half of the claim: the intermediate is present and is not the leaf.
    x509m, _h, serialization, _r, _n = _crypto()
    chain_certs = x509m.load_pem_x509_certificates(served_chain.encode())
    chain_subjects = [c.subject.rfc4514_string() for c in chain_certs]
    assert chain_subjects == [inter.subject.rfc4514_string(), root.subject.rfc4514_string()], (
        "CertificateChain must be the CA path in the order it was imported "
        f"(<intermediate>, <root>); got {chain_subjects!r}"
    )

    tmpdir = tempfile.mkdtemp(prefix="sim2real-acm-chain-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))

    # (2) POSITIVE CONTROL, run first as the barrier: leaf + chain verifies and carries data.
    good_port, good_stop, good_box = _tls_echo_server(
        served_leaf.encode() + b"\n" + served_chain.encode(), _key_pem(leaf_key), tmpdir, "full")
    ctx.on_cleanup(good_stop)
    good = _tls_connect(good_port, _pem(root), host, nonce, tmpdir, "root")
    assert good["echo"] == nonce, (
        "the control handshake with Certificate+CertificateChain must succeed and echo the "
        f"nonce; got {good['echo']!r} (server error {good_box.get('server_error')!r})"
    )
    good_stop()

    # (3) Break exactly one thing: serve the leaf ALONE, same client, same trust store, same host.
    bad_port, bad_stop, bad_box = _tls_echo_server(
        served_leaf.encode(), _key_pem(leaf_key), tmpdir, "leafonly")
    ctx.on_cleanup(bad_stop)
    captured = None
    try:
        leaked = _tls_connect(bad_port, _pem(root), host, nonce, tmpdir, "root")
    except ssl.SSLCertVerificationError as exc:
        captured = exc
    else:
        raise AssertionError(
            "serving ONLY GetCertificate's `Certificate` field must fail path validation against "
            "a client that trusts only the root -- the intermediate is genuinely required. The "
            f"handshake instead completed: {leaked['version']!r}, echo {leaked['echo']!r}. That "
            "means the `Certificate` field already contained the chain."
        )
    # (4) The failure is the specific one path validation produces, not a transport error.
    assert captured.verify_code == 20, (
        f"expected OpenSSL verify_code 20 (unable to get local issuer certificate); got "
        f"{captured.verify_code!r} / {captured.verify_message!r}"
    )
    assert captured.verify_message == "unable to get local issuer certificate", (
        f"expected verify_message 'unable to get local issuer certificate'; got "
        f"{captured.verify_message!r}"
    )
    # (5) Effect absent: the failed handshake carried no application data. Under TLS 1.3 the
    #     server may finish its half before the client's alert, so this checks the payload, not a
    #     server error, and only after `bad_stop` joins the server thread.
    bad_stop()
    assert not bad_box.get("payload"), (
        "the client aborted during verification, so the server must never have received the "
        f"nonce; it received {bad_box.get('payload')!r} (expected nothing). Server box: "
        f"{bad_box!r}"
    )

    # (6) And the certificate is untouched by any of this -- still ISSUED and still serving.
    after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert after["Status"] == "ISSUED", (
        f"the certificate must be unaffected by a client-side verification failure; Status is "
        f"{after['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
