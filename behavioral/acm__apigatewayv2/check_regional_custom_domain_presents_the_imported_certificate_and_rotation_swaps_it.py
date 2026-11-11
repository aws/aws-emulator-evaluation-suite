"""regional-custom-domain-presents-the-imported-certificate-and-rotation-swaps-it."""
from __future__ import annotations

import datetime
import os
import re
import shutil
import socket
import ssl
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regional-custom-domain-presents-the-imported-certificate-and-rotation-swaps-it"
GROUP = "data-plane"
SERVICES = ["acm", "apigatewayv2"]

_STATUS_LINE_RE = re.compile(r"^HTTP/1\.[01] (\d{3}) ")


_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=8, base_delay=5.0):
    """Retry fn() on throttle codes; CreateDomainName throttles hard after ImportCertificate."""
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
    """Lazily import `cryptography`. Absence is a FAIL, never a skip."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise AssertionError(
            f"cryptography is required to mint the two X.509 leaves this rotation needs: {exc}"
        ) from None
    return x509, hashes, serialization, rsa, NameOID


def _subject(cn):
    x509, _h, _s, _r, NameOID = _crypto()
    assert len(cn) <= 64, f"CN {cn!r} is {len(cn)} chars; X.509 caps it at 64"
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-xsvc-acm-not-a-real-key"),
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
    """A self-signed RSA-2048 CA. It signs BOTH leaves, so the client's trust decision is
    constant and only the LEAF can explain a difference across the rotation."""
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
    """A server certificate signed by `issuer_key`, carrying `sans` as DNS names.

    The SAN matters: Python's `ssl` implements RFC 6125 and ignores the subject CN entirely.
    """
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


def _client_context(trust_pem, tmpdir):
    """A verifying client context trusting ONLY `trust_pem`, hostname checking ON."""
    trust_path = os.path.join(tmpdir, "apigw-trust.pem")
    with open(trust_path, "wb") as handle:
        handle.write(trust_pem)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cafile=trust_path)
    client_ctx.check_hostname = True
    client_ctx.verify_mode = ssl.CERT_REQUIRED
    return client_ctx


def _request(ctx, client_ctx, gateway_host, custom_domain, path="/"):
    """One verified HTTPS GET to the REGIONAL gateway host, with SNI/Host = the custom domain.

    Raises on any transport or verification failure; callers decide what that means.
    """
    payload = (f"GET {path} HTTP/1.1\r\nHost: {custom_domain}\r\n"
               f"Connection: close\r\nUser-Agent: sim2real-xsvc-apigwv2\r\n\r\n").encode()
    with socket.create_connection(ctx.endpoint_host(gateway_host, 443), timeout=15) as raw:
        with client_ctx.wrap_socket(raw, server_hostname=custom_domain) as tls:
            peer_der = tls.getpeercert(binary_form=True)
            version = tls.version()
            tls.sendall(payload)
            body = b""
            while True:
                chunk = tls.recv(8192)
                if not chunk:
                    break
                body += chunk
    head, _sep, rest = body.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n")[0].decode(errors="replace")
    return {"status_line": status_line, "body": rest, "peer_der": peer_der, "version": version}


def _wait_for_tls(ctx, client_ctx, gateway_host, custom_domain, *, timeout_s, interval_s, description):
    """Poll until a verified handshake to the custom domain completes; unconnectable is a FAIL.

    `gaierror` is retried: the dedicated host's DNS record lags DomainNameStatus=AVAILABLE.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return _request(ctx, client_ctx, gateway_host, custom_domain)
        except (OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(interval_s)
    raise AssertionError(
        f"{description}: {gateway_host!r} never completed a verified TLS handshake for SNI "
        f"{custom_domain!r} within {timeout_s}s. Last error: {last}"
    )




@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A REGIONAL API Gateway v2 custom domain presents its imported ACM certificate byte for byte
    over TLS (SNI = the domain, TLS >= 1.2, unmapped host answers 403), and UpdateDomainName with a
    new CertificateArn swaps the presented leaf stably.

    Reference: https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/v2-domainnames-domainname.html
    """
    acm = ctx.client("acm")
    apigw = ctx.client("apigatewayv2")

    uid = ctx.unique_name("sim2real-xsvc-agwv2-")
    domain = f"{uid}.example.com"

    root, root_key = _root_ca(f"root-{uid}")
    leaf_old, key_old = _leaf(domain, [domain], f"root-{uid}", root_key)
    leaf_new, key_new = _leaf(domain, [domain], f"root-{uid}", root_key)
    assert leaf_old.serial_number != leaf_new.serial_number, (
        "the two leaves must have distinct serials or the rotation is unobservable")

    def _import(leaf, key):
        arn = _retry_throttle(lambda: acm.import_certificate(
            Certificate=_pem(leaf), PrivateKey=_key_pem(key), CertificateChain=_pem(root),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ))["CertificateArn"]

        def _delete():
            for _ in range(24):
                try:
                    acm.delete_certificate(CertificateArn=arn)
                    return
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceInUseException":
                        raise
                    time.sleep(5)
            raise RuntimeError(f"acm certificate still in use, not deleted: {arn}")

        ctx.on_cleanup(_delete)
        _poll_until(
            lambda: _retry_throttle(
                lambda: acm.describe_certificate(CertificateArn=arn))["Certificate"]["Status"],
            lambda status: status == "ISSUED",
            timeout_s=120, interval_s=3,
            description=f"the imported certificate {arn} reaching ISSUED",
        )
        return arn

    old_arn = _import(leaf_old, key_old)
    new_arn = _import(leaf_new, key_new)

    created = _retry_throttle(lambda: apigw.create_domain_name(
        DomainName=domain,
        DomainNameConfigurations=[{
            "CertificateArn": old_arn,
            "EndpointType": "REGIONAL",
            "SecurityPolicy": "TLS_1_2",
        }],
        Tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain))
    assert created["DomainNameConfigurations"][0]["CertificateArn"] == old_arn, (
        f"CreateDomainName must record the certificate it was given; it reports "
        f"{created['DomainNameConfigurations'][0]['CertificateArn']!r}, expected {old_arn!r}"
    )

    config = _poll_until(
        lambda: _retry_throttle(
            lambda: apigw.get_domain_name(DomainName=domain))["DomainNameConfigurations"][0],
        lambda cfg: cfg["DomainNameStatus"] == "AVAILABLE",
        timeout_s=300, interval_s=10,
        description=f"the REGIONAL custom domain {domain!r} reaching AVAILABLE",
    )
    gateway_host = config["ApiGatewayDomainName"]
    assert gateway_host, (
        f"an AVAILABLE REGIONAL domain must expose an ApiGatewayDomainName to point DNS at; "
        f"GetDomainName returned {config!r}"
    )
    assert config["SecurityPolicy"] == "TLS_1_2", (
        f"the domain must report the security policy it was created with; got "
        f"{config['SecurityPolicy']!r}"
    )

    tmpdir = tempfile.mkdtemp(prefix="sim2real-xsvc-apigwv2-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    client_ctx = _client_context(_pem(root), tmpdir)
    x509m, _h, serialization, _r, _n = _crypto()

    # (1) Positive control: a verified handshake completes. The dedicated host's DNS record can lag
    #     DomainNameStatus=AVAILABLE by several minutes, hence the longer budget.
    first = _wait_for_tls(
        ctx, client_ctx, gateway_host, domain, timeout_s=600, interval_s=10,
        description="the custom domain beginning to terminate TLS")

    # (2) The certificate on the wire is the certificate imported into ACM, byte for byte.
    old_der = leaf_old.public_bytes(serialization.Encoding.DER)
    assert first["peer_der"] == old_der, (
        f"the custom domain must present the ACM certificate configured on it: it presented "
        f"serial "
        f"{x509m.load_der_x509_certificate(first['peer_der']).serial_number:x}, expected the "
        f"imported {leaf_old.serial_number:x}"
    )

    # (3) The SecurityPolicy floor, one-sided: a client offering TLS 1.1 is not portable.
    assert first["version"] in ("TLSv1.2", "TLSv1.3"), (
        f"a domain whose SecurityPolicy is TLS_1_2 must not negotiate below TLS 1.2; the "
        f"handshake negotiated {first['version']!r}"
    )

    # (4) The HTTP layer behind the TLS terminator is live: an unmapped custom domain answers a
    #     well-formed 403, not silence and not a 5xx.
    match = _STATUS_LINE_RE.match(first["status_line"])
    assert match is not None, (
        f"the tunnel must carry a well-formed HTTP response, proving API Gateway is behind the "
        f"TLS terminator; got status line {first['status_line']!r}"
    )
    assert match.group(1) == "403", (
        f"a custom domain with no API mapping must answer 403 Forbidden; got "
        f"{first['status_line']!r} with body {first['body'][:160]!r}"
    )

    # (5) THE MUTATION: rotate the certificate on the live custom domain.
    _retry_throttle(lambda: apigw.update_domain_name(
        DomainName=domain,
        DomainNameConfigurations=[{
            "CertificateArn": new_arn,
            "EndpointType": "REGIONAL",
            "SecurityPolicy": "TLS_1_2",
        }],
    ))

    # (6) Real clients are now presented the NEW leaf; the host already resolves, so only TLS
    #     certificate selection has to change.
    def _presented():
        try:
            result = _request(ctx, client_ctx, gateway_host, domain)
        except (OSError, ssl.SSLError) as exc:
            return f"<handshake: {type(exc).__name__}: {exc}>"
        return x509m.load_der_x509_certificate(result["peer_der"]).serial_number

    _poll_until(
        _presented,
        lambda serial: serial == leaf_new.serial_number,
        timeout_s=300, interval_s=10,
        description=(
            f"the custom domain presenting the rotated-in leaf (serial "
            f"{leaf_new.serial_number:x}) instead of {leaf_old.serial_number:x}"
        ),
    )

    # (7) The swap is STABLE, not flapping, and the HTTP layer survived it.
    new_der = leaf_new.public_bytes(serialization.Encoding.DER)
    for attempt in range(3):
        result = _request(ctx, client_ctx, gateway_host, domain)
        assert result["peer_der"] == new_der, (
            f"handshake {attempt + 1} of 3 after the rotation presented serial "
            f"{x509m.load_der_x509_certificate(result['peer_der']).serial_number:x}, expected "
            f"{leaf_new.serial_number:x} -- the swap must be stable, not alternating"
        )
        after_match = _STATUS_LINE_RE.match(result["status_line"])
        assert after_match is not None and after_match.group(1) == "403", (
            f"the custom domain must still answer 403 after the rotation; handshake "
            f"{attempt + 1} of 3 got {result['status_line']!r}"
        )

    # (8) And the consumer's control plane agrees about what it is serving.
    final = _poll_until(
        lambda: _retry_throttle(
            lambda: apigw.get_domain_name(DomainName=domain))["DomainNameConfigurations"][0],
        lambda cfg: cfg["CertificateArn"] == new_arn
        and cfg["DomainNameStatus"] == "AVAILABLE",
        timeout_s=300, interval_s=10,
        description="GetDomainName reporting the rotated-in certificate on an AVAILABLE domain",
    )
    assert final["CertificateArn"] == new_arn, (
        f"GetDomainName must report the rotated-in certificate; got "
        f"{final['CertificateArn']!r}, expected {new_arn!r}"
    )
    assert final["SecurityPolicy"] == "TLS_1_2", (
        f"the rotation must not silently change the security policy; got "
        f"{final['SecurityPolicy']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
