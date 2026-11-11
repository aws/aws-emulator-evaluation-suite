"""regional-custom-domain-refuses-a-pending-certificate-then-serves-the-issued-one."""
from __future__ import annotations

import datetime
import os
import re
import shutil
import socket
import ssl
import tempfile
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regional-custom-domain-refuses-a-pending-certificate-then-serves-the-issued-one"
GROUP = "overly-permissive"
SERVICES = ["acm", "apigateway"]

_STATUS_LINE_RE = re.compile(r"^HTTP/1\.[01] (\d{3}) ")

def _is_ipv4(value: str) -> bool:
    """True only for a dotted-quad address, so a resolver diagnostic never reaches connect."""
    try:
        socket.inet_aton(value)
    except OSError:
        return False
    return value.count(".") == 3



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


def _refusal(fn):
    """The ClientError raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(
        "the call was expected to be REFUSED and instead succeeded; an over-permissive target "
        "must not be able to pass this check by accepting the request"
    )


def _delete_domain(apigw, domain):
    """Teardown DeleteDomainName; only NotFoundException (already deleted) counts as gone."""
    try:
        _retry_throttle(lambda: apigw.delete_domain_name(domainName=domain))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _crypto():
    """Lazily import `cryptography`; an absent module raises ImportError."""
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
    """A self-signed RSA-2048 CA, used as the probing client's ONLY trust anchor."""
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


def _request(ctx, client_ctx, connect_host, custom_domain):
    """One verified HTTPS GET, TCP to `connect_host` (an IP), TLS SNI/Host = `custom_domain`."""
    payload = (f"GET / HTTP/1.1\r\nHost: {custom_domain}\r\n"
               f"Connection: close\r\nUser-Agent: sim2real-xsvc-apigw\r\n\r\n").encode()
    with socket.create_connection(ctx.endpoint_host(connect_host, 443), timeout=15) as raw:
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
    return {"status_line": head.split(b"\r\n")[0].decode(errors="replace"),
            "body": rest, "peer_der": peer_der, "version": version}


def _wait_for_tls(ctx, client_ctx, connect_host, custom_domain, *, timeout_s, description):
    """Poll until a VERIFIED handshake completes. Unconnectable-but-configured is a FAIL."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return _request(ctx, client_ctx, connect_host, custom_domain)
        except (OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(5)
    raise AssertionError(
        f"{description}: {connect_host!r} never completed a verified TLS handshake for SNI "
        f"{custom_domain!r} within {timeout_s}s. Last error: {last}"
    )


def _domain_names(apigw):
    """Every custom domain name API Gateway holds, following the paginator."""
    names = set()
    for page in apigw.get_paginator("get_domain_names").paginate():
        for item in page["items"]:
            names.add(item["domainName"])
    return names


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateDomainName refuses a PENDING_VALIDATION certificate with BadRequestException,
    then, given an ISSUED imported one, the custom domain presents exactly that certificate.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-regional-api-custom-domain-create.html
    Reference: https://docs.aws.amazon.com/apigateway/latest/api/API_CreateDomainName.html
    """
    acm = ctx.client("acm")
    apigw = ctx.client("apigateway")
    route53 = ctx.client("route53")

    uid = ctx.unique_name("sim2real-xsvc-agw-")
    # A random parent under a real TLD keeps the requested certificate PENDING_VALIDATION;
    # a reserved name such as example.com is fast-failed to FAILED instead.
    parent = f"sim2realprobe{uuid.uuid4().hex[:10]}.com"
    domain = f"{uid}.{parent}"

    # Imported, so it is ISSUED without any domain proof.
    root, root_key = _root_ca(f"root-{uid}")
    leaf, leaf_key = _leaf(domain, [domain], f"root-{uid}", root_key)
    issued_arn = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf), PrivateKey=_key_pem(leaf_key), CertificateChain=_pem(root),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]

    def _delete_issued():
        for _ in range(24):
            try:
                acm.delete_certificate(CertificateArn=issued_arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceInUseException":
                    raise
                time.sleep(5)
        raise RuntimeError(f"acm certificate still in use, not deleted: {issued_arn}")

    ctx.on_cleanup(_delete_issued)
    _poll_until(
        lambda: _retry_throttle(lambda: acm.describe_certificate(
            CertificateArn=issued_arn))["Certificate"]["Status"],
        lambda status: status == "ISSUED",
        timeout_s=120, interval_s=3,
        description="the imported certificate reaching ISSUED",
    )

    pending_arn = _retry_throttle(lambda: acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        IdempotencyToken=uuid.uuid4().hex[:24],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=pending_arn), attempts=4, base_delay=3.0))

    def _create(certificate_arn):
        return apigw.create_domain_name(
            domainName=domain,
            regionalCertificateArn=certificate_arn,
            endpointConfiguration={"types": ["REGIONAL"]},
            securityPolicy="TLS_1_2",
            tags={"sim2real": CHECK},
        )

    created = _retry_throttle(lambda: _create(issued_arn))
    ctx.on_cleanup(lambda: _delete_domain(apigw, domain))
    assert created["regionalCertificateArn"] == issued_arn, (
        f"CreateDomainName must record the certificate it was given; it reports "
        f"{created['regionalCertificateArn']!r}, expected {issued_arn!r}"
    )
    # Remove it again so beat 2 exercises the same CREATE path, not an update path.
    apigw.delete_domain_name(domainName=domain)
    _poll_until(
        lambda: _domain_names(apigw),
        lambda names: domain not in names,
        timeout_s=120, interval_s=5,
        description="the control domain disappearing so the refused create is a true CREATE",
    )

    # Re-read so the refusal cannot be attributed to a FAILED certificate.
    pending_detail = _retry_throttle(lambda: acm.describe_certificate(
        CertificateArn=pending_arn))["Certificate"]
    assert pending_detail["Status"] == "PENDING_VALIDATION", (
        f"the negative's certificate must be PENDING_VALIDATION at the moment of the refused "
        f"call, or the refusal is attributable to something else; ACM reports "
        f"{pending_detail['Status']!r} (FailureReason {pending_detail.get('FailureReason')!r})"
    )

    error = _refusal(lambda: _create(pending_arn))
    code = error.response["Error"]["Code"]
    assert code == "BadRequestException", (
        f"attaching a PENDING_VALIDATION certificate to a REGIONAL custom domain must be "
        f"refused with BadRequestException; got {code!r} ({error.response['Error'].get('Message')!r})"
    )
    message = error.response["Error"].get("Message", "")
    assert message == "Certificate is not in an ISSUED state, and cannot be used", (
        f"the refusal must name the certificate STATE, so that it stays distinguishable from a "
        f"malformed-ARN refusal (a format failure, never a state one); the message was {message!r}"
    )

    names = _domain_names(apigw)
    assert domain not in names, (
        f"the refused CreateDomainName must leave no custom domain behind; GetDomainNames lists "
        f"{domain!r} among {len(names)} domains"
    )

    restored = _retry_throttle(lambda: _create(issued_arn))
    ctx.on_cleanup(lambda: _delete_domain(apigw, domain))
    assert restored["regionalCertificateArn"] == issued_arn, (
        f"the restored domain must carry the ISSUED certificate; got "
        f"{restored['regionalCertificateArn']!r}, expected {issued_arn!r}"
    )

    config = _poll_until(
        lambda: _retry_throttle(lambda: apigw.get_domain_name(domainName=domain)),
        lambda item: item["domainNameStatus"] == "AVAILABLE",
        timeout_s=300, interval_s=10,
        description=f"the REGIONAL custom domain {domain!r} reaching AVAILABLE",
    )
    gateway_host = config["regionalDomainName"]
    hosted_zone_id = config["regionalHostedZoneId"]
    assert gateway_host and hosted_zone_id, (
        f"an AVAILABLE REGIONAL domain must expose a regionalDomainName AND a "
        f"regionalHostedZoneId to build a Route 53 ALIAS at; GetDomainName returned {config!r}"
    )

    # regionalDomainName is a Route 53 ALIAS target with no public record of its own, so the
    # check builds its own hosted zone with an ALIAS to it, as the developer guide does.
    zone = route53.create_hosted_zone(
        Name=parent, CallerReference=uuid.uuid4().hex,
        HostedZoneConfig={"Comment": CHECK},
    )
    zone_id = zone["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))
    route53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=zone_id.rsplit("/", 1)[-1],
        AddTags=[{"Key": "sim2real", "Value": CHECK}],
    )
    name_servers = zone["DelegationSet"]["NameServers"]
    assert name_servers, f"a freshly created hosted zone must carry name servers; got {zone!r}"

    alias_record = {
        "Name": domain,
        "Type": "A",
        "AliasTarget": {
            "DNSName": gateway_host, "HostedZoneId": hosted_zone_id,
            "EvaluateTargetHealth": False,
        },
    }
    change = route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": "CREATE", "ResourceRecordSet": alias_record}]},
    )
    ctx.on_cleanup(lambda: route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": alias_record}]},
    ))
    _poll_until(
        lambda: route53.get_change(Id=change["ChangeInfo"]["Id"])["ChangeInfo"]["Status"],
        lambda status: status == "INSYNC",
        timeout_s=120, interval_s=5,
        description="the ALIAS record for the custom domain reaching INSYNC",
    )

    def _resolve_via_zone_ns():
        # TestDNSAnswer over HTTPS needs no outbound UDP 53, which the runner network may drop.
        answer = route53.test_dns_answer(
            HostedZoneId=zone_id, RecordName=domain, RecordType="A",
        )
        if answer.get("ResponseCode") != "NOERROR":
            return []
        return [ip for ip in answer.get("RecordData", []) if _is_ipv4(ip)]

    resolved_ips = _poll_until(
        _resolve_via_zone_ns,
        lambda ips: bool(ips),
        timeout_s=60, interval_s=5,
        description=(
            f"the custom domain {domain!r} resolving an A record at its own zone's "
            f"authoritative name servers {name_servers!r} (via Route 53 TestDNSAnswer)"
        ),
    )
    connect_host = resolved_ips[0]

    tmpdir = tempfile.mkdtemp(prefix="sim2real-xsvc-apigw-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    client_ctx = _client_context(_pem(root), tmpdir)
    result = _wait_for_tls(
        ctx, client_ctx, connect_host, domain, timeout_s=60,
        description="the restored custom domain beginning to terminate TLS")

    x509m, _h, serialization, _r, _n = _crypto()
    local_der = leaf.public_bytes(serialization.Encoding.DER)
    assert result["peer_der"] == local_der, (
        f"the custom domain must present the ISSUED certificate it was configured with: it "
        f"presented serial "
        f"{x509m.load_der_x509_certificate(result['peer_der']).serial_number:x}, expected the "
        f"imported {leaf.serial_number:x}"
    )
    assert result["version"] in ("TLSv1.2", "TLSv1.3"), (
        f"a domain whose securityPolicy is TLS_1_2 must not negotiate below TLS 1.2; the "
        f"handshake negotiated {result['version']!r}"
    )
    match = _STATUS_LINE_RE.match(result["status_line"])
    assert match is not None, (
        f"the tunnel must carry a well-formed HTTP response, proving API Gateway is behind the "
        f"TLS terminator rather than only a TLS listener; got {result['status_line']!r}"
    )
    assert match.group(1) == "403", (
        f"a custom domain with no base path mapping must answer 403; got "
        f"{result['status_line']!r} with body {result['body'][:160]!r}"
    )

    final = _domain_names(apigw)
    assert domain in final, (
        f"the restored custom domain must be listed by GetDomainNames; {domain!r} was absent "
        f"from {len(final)} domains"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
