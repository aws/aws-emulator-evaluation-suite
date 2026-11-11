"""acm-reimport-with-a-mismatched-private-key-rejected."""
from __future__ import annotations

import datetime
import hashlib
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-reimport-with-a-mismatched-private-key-rejected"
GROUP = 'overly-permissive'
SERVICES = ['acm']

_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]

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


def _error_code(fn):
    """The AWS (code, HTTP status, message) raised by fn(); RAISES if it unexpectedly SUCCEEDS.

    Returning a falsy value on success would turn the strongest possible signal -- input real AWS
    refuses being accepted -- into an error-code mismatch that reads like a naming difference.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(
        f"the call was expected to be REFUSED but it succeeded, returning {result!r}"
    )


def _stored_serial(acm, arn):
    """The serial of the certificate ACM actually stores, parsed from GetCertificate's PEM.
    DescribeCertificate's `Serial` is a rendering (colon-hex on AWS) and is not compared."""
    x509, _h, _s, _r, _n = _crypto()
    pem = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))["Certificate"]
    return x509.load_pem_x509_certificate(pem.encode()).serial_number


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


def _arns_for_domain(acm, domain):
    """Every certificate ARN in the account carrying `domain` as DomainName, fully paginated.

    The default ListCertificates keyTypes filter is narrower than the enum, and the account may
    hold many other certificates, so both the widened filter and the NextToken loop are
    load-bearing.
    """
    out = []
    for page in acm.get_paginator("list_certificates").paginate(
            Includes={"keyTypes": list(_ALL_KEY_TYPES)}):
        for summary in page["CertificateSummaryList"]:
            if summary.get("DomainName") == domain:
                out.append(summary["CertificateArn"])
    return out


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
            return {"echo": echoed, "peer": tls.getpeercert(),
                    "peer_der": tls.getpeercert(binary_form=True)}


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A re-import whose PrivateKey does not match its Certificate is refused with
    ValidationException, and the material already stored under that ARN is left intact and still
    terminates TLS; the same re-import with a matched pair succeeds (positive control)."""
    acm = ctx.client("acm")
    uid = ctx.unique_name("sim2real-behav-remis-")
    host = f"{uid}.example.com"
    nonce = f"sim2real-nonce-{uid}".encode()

    root, root_key = _root_ca(f"root-{uid}")
    leaf_a, key_a = _leaf(host, [host], f"root-{uid}", root_key)
    leaf_b, _key_b = _leaf(host, [host], f"root-{uid}", root_key)
    leaf_c, key_c = _leaf(host, [host], f"root-{uid}", root_key)
    assert len({leaf_a.serial_number, leaf_b.serial_number, leaf_c.serial_number}) == 3, (
        "the three generated leaves must have distinct serials for the assertions below to "
        f"discriminate; got {hex(leaf_a.serial_number)}, {hex(leaf_b.serial_number)}, "
        f"{hex(leaf_c.serial_number)}"
    )

    resp = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf_a), PrivateKey=_key_pem(key_a), CertificateChain=_pem(root),
        Tags=[{"Key": "sim2real", "Value": CHECK}]))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0))

    before = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED" and d.get("Serial"),
        timeout_s=120, interval_s=3,
        description="the base imported certificate reaches ISSUED with a parsed Serial",
    )
    stored_a = _stored_serial(acm, arn)
    assert stored_a == leaf_a.serial_number, (
        f"the stored certificate's serial {stored_a:x} must be leaf A's serial "
        f"{leaf_a.serial_number:x}"
    )
    pem_a = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))["Certificate"]
    sha_a = hashlib.sha256(pem_a.strip().encode()).hexdigest()

    tmpdir = tempfile.mkdtemp(prefix="sim2real-acm-remis-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))

    # (1) BARRIER: what ACM stores today is usable. Established before anything is broken, so the
    #     post-refusal handshake below cannot be passing for a "not ready yet" reason.
    try:
        port0, stop0, box0 = _tls_echo_server(
            pem_a.encode() + b"\n" + _pem(root), _key_pem(key_a), tmpdir, "pre")
        ctx.on_cleanup(stop0)
        pre = _tls_connect(port0, _pem(root), host, nonce, tmpdir, "root")
    except (ssl.SSLError, OSError) as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: the certificate GetCertificate returned for {arn} could not "
            f"terminate a TLS handshake before any refusal was attempted: {type(exc).__name__}: {exc}"
        ) from exc
    assert pre["echo"] == nonce, (
        "the barrier handshake against the stored certificate must succeed before the refusal is "
        f"attempted; got {pre['echo']!r} (server error {box0.get('server_error')!r})"
    )
    stop0()

    # (2) Break exactly one thing: leaf B's certificate paired with leaf A's private key.
    code, status, message = _error_code(lambda: acm.import_certificate(
        CertificateArn=arn, Certificate=_pem(leaf_b), PrivateKey=_key_pem(key_a),
        CertificateChain=_pem(root)))
    assert code == "ValidationException", (
        f"re-importing a certificate whose key does not match must raise 'ValidationException'; "
        f"got {code!r}"
    )
    assert status == 400, f"expected HTTP 400 for the mismatched-key re-import, got {status!r}"
    expected_message = "Key provided does not match the certificate."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # (3) EFFECT ABSENT, metadata: the ARN still describes leaf A.
    after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert after["Serial"] == before["Serial"], (
        f"the refused re-import must not have changed the stored Serial; it was "
        f"{before['Serial']!r} and is now {after['Serial']!r} "
        f"(leaf B's serial is {leaf_b.serial_number:x})"
    )
    assert after["Status"] == "ISSUED", f"Status after the refusal was {after['Status']!r}"
    assert after["CertificateArn"] == arn, (
        f"the ARN must be stable across a refused re-import; got {after['CertificateArn']!r}"
    )
    # (4) EFFECT ABSENT, content: the PEM is byte-identical to what it was.
    pem_now = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))["Certificate"]
    assert hashlib.sha256(pem_now.strip().encode()).hexdigest() == sha_a, (
        "GetCertificate must return the pre-refusal bytes unchanged; sha256 was "
        f"{sha_a!r} and is now {hashlib.sha256(pem_now.strip().encode()).hexdigest()!r}"
    )
    # (5) EFFECT ABSENT, no second resource: exactly one certificate carries this domain.
    #     MEASURED: ListCertificates is eventually consistent -- it returned 0 rows for a
    #     certificate DescribeCertificate had already reported ISSUED -- so the membership poll
    #     is what makes the count meaningful rather than a race.
    listed = _poll_until(
        lambda: _arns_for_domain(acm, host),
        lambda arns: arn in arns,
        timeout_s=180, interval_s=5,
        description="the imported certificate is indexed in ListCertificates",
    )
    assert listed == [arn], (
        f"the refused re-import must not have minted a second certificate for {host!r}; the "
        f"paginated list holds {listed!r}"
    )
    # (6) EFFECT ABSENT, cryptographic: the stored material still terminates TLS, and still
    #     presents leaf A. This is what a "replayed the error, corrupted the slot" emulator fails.
    port1, stop1, box1 = _tls_echo_server(
        pem_now.encode() + b"\n" + _pem(root), _key_pem(key_a), tmpdir, "post")
    ctx.on_cleanup(stop1)
    post = _tls_connect(port1, _pem(root), host, nonce, tmpdir, "root")
    assert post["echo"] == nonce, (
        "after the refusal the stored certificate must still terminate TLS with leaf A's key; "
        f"got {post['echo']!r} (server error {box1.get('server_error')!r})"
    )
    assert int(post["peer"]["serialNumber"], 16) == leaf_a.serial_number, (
        f"the certificate still served is serial {int(post['peer']['serialNumber'], 16):x}, "
        f"expected leaf A's {leaf_a.serial_number:x}"
    )
    stop1()

    # (7) POSITIVE CONTROL: the same operation with a matched pair succeeds, into the same ARN.
    ctrl = _retry_throttle(lambda: acm.import_certificate(
        CertificateArn=arn, Certificate=_pem(leaf_c), PrivateKey=_key_pem(key_c),
        CertificateChain=_pem(root)))
    assert ctrl["CertificateArn"] == arn, (
        f"a successful re-import must reuse the ARN, not mint one; got {ctrl['CertificateArn']!r}"
    )
    ctrl_detail = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("Serial") and _stored_serial(acm, arn) == leaf_c.serial_number,
        timeout_s=120, interval_s=3,
        description="the control re-import's serial becomes visible",
    )
    stored_c = _stored_serial(acm, arn)
    assert stored_c == leaf_c.serial_number, (
        f"after the control re-import the stored serial must be leaf C's {leaf_c.serial_number:x}; "
        f"got {stored_c:x} (Serial rendered {ctrl_detail['Serial']!r})"
    )
    ctrl_pem = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))["Certificate"]
    assert ctrl_pem.strip() == _pem(leaf_c).decode().strip(), (
        "the control re-import must have replaced the served bytes with leaf C's; got "
        f"{ctrl_pem[:60]!r}..."
    )
    assert _arns_for_domain(acm, host) == [arn], (
        f"a successful re-import must not mint a second certificate for {host!r} either; the "
        f"paginated list holds {_arns_for_domain(acm, host)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
