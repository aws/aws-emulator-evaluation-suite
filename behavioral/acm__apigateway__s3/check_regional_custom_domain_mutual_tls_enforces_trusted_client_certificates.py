"""regional-custom-domain-mutual-tls-enforces-trusted-client-certificates."""
from __future__ import annotations

import datetime
import os
import shutil
import socket
import ssl
import tempfile
import time

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from behavioral_harness import tags

CHECK = "regional-custom-domain-mutual-tls-enforces-trusted-client-certificates"
GROUP = "data-plane"
SERVICES = ["acm", "apigateway", "s3"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}

_THROTTLE_CODES = ("TooManyRequestsException", "ThrottlingException", "Throttling")

# The TLS alerts a server sends when it requires a client certificate and the client sent none:
# certificate_required after a TLS 1.3 handshake, handshake_failure during a TLS 1.2 one.
_NO_CERTIFICATE_ALERTS = ("TLSV13_ALERT_CERTIFICATE_REQUIRED", "SSLV3_ALERT_HANDSHAKE_FAILURE")


# ===== helpers (self-contained) =====


def _retry_throttle(fn, *, attempts=8, base_delay=3.0):
    """Call fn(), retrying only a throttle code with linear backoff."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (attempt + 1))
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); return it. RAISES on timeout, never returns stale."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _dns_baseline(route53):
    """The account's DNS baseline: (apex domain, hosted zone id) of the zone carrying
    _BASELINE_TAG. Fails, never skips, when the account has no baseline."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            if zone["Config"].get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=zone_id
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                return zone["Name"].rstrip("."), zone_id
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has no domain to "
        "request a validated certificate on"
    )


def _issue_public_certificate(ctx, acm, route53, zone_id, domain):
    """A publicly-issued, DNS-validated ACM certificate for `domain`. Registers cleanup for both
    the validation record and the certificate immediately."""
    cert_arn = _retry_throttle(lambda: acm.request_certificate(
        DomainName=domain, ValidationMethod="DNS",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_free(acm, cert_arn))

    record = _poll_until(
        ctx,
        lambda: (acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
                 .get("DomainValidationOptions", [{}])[0].get("ResourceRecord")),
        lambda r: r is not None,
        timeout_s=60, interval_s=3,
        description="ACM publishing the DNS validation record for the requested certificate",
    )
    change = {
        "ResourceRecordSet": {
            "Name": record["Name"], "Type": record["Type"], "TTL": 60,
            "ResourceRecords": [{"Value": record["Value"]}],
        }
    }
    route53.change_resource_record_sets(
        HostedZoneId=zone_id, ChangeBatch={"Changes": [{"Action": "CREATE", **change}]},
    )
    ctx.on_cleanup(lambda: route53.change_resource_record_sets(
        HostedZoneId=zone_id, ChangeBatch={"Changes": [{"Action": "DELETE", **change}]},
    ))
    _poll_until(
        ctx,
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["Status"],
        lambda status: status == "ISSUED",
        timeout_s=300, interval_s=10,
        description=f"the certificate for {domain!r} reaching ISSUED via DNS validation",
    )
    return cert_arn


def _delete_certificate_when_free(acm, cert_arn, *, attempts=24, interval_s=5.0):
    """Delete cert_arn, retrying while another resource still references it. RAISES if it
    never frees up within the budget."""
    for _ in range(attempts):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate {cert_arn} still in use after the cleanup budget")


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _subject(cn):
    assert len(cn) <= 64, f"CN {cn!r} is {len(cn)} chars; X.509 caps it at 64"
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _root_ca(cn):
    """A self-signed RSA-2048 CA, used only as a client-certificate issuer."""
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


def _client_leaf(cn, issuer_cn, issuer_key):
    """A CLIENT_AUTH leaf certificate signed by issuer_key."""
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn)).issuer_name(_subject(issuer_cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key):
    """PEM-serialise a key generated moments ago in this process. It is not a credential."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write_pem(tmpdir, name, data):
    path = os.path.join(tmpdir, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def _client_ssl_context(verify, cert_path=None, key_path=None):
    """A fresh client context honouring ``ctx.http_verify`` (True, False, or a CA bundle path),
    optionally presenting a client certificate. Built new per connection so no TLS session ticket
    from an earlier handshake carries authentication state into this one."""
    ssl_ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    if verify is False:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    if cert_path:
        ssl_ctx.load_cert_chain(cert_path, key_path)
    return ssl_ctx


def _caller_credentials(ctx):
    """The harness's per-run credentials, via the one sanctioned seam (never the ambient chain)."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    return akid, secret, env.get("AWS_SESSION_TOKEN")


def _signed_headers(ctx, host, path):
    """Headers of a GET for https://{host}{path}, SigV4-signed for execute-api in ctx.region."""
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    # tls: mutual TLS on the custom domain is the subject, so the signed request names that host
    req = AWSRequest(method="GET", url=f"https://{host}{path}", headers={"Host": host})
    SigV4Auth(Credentials(*_caller_credentials(ctx)), "execute-api", ctx.region).add_auth(req)
    return dict(req.headers.items())


def _request(ctx, gateway_host, custom_domain, *, cert_path=None, key_path=None, path="/"):
    """One SigV4-signed HTTPS GET to the REGIONAL gateway host, SNI/Host = the custom domain, on
    a freshly built TLS context. Raises on any transport or handshake failure; callers decide
    what that means. A connection closed with no response returns status None."""
    ssl_ctx = _client_ssl_context(ctx.http_verify, cert_path, key_path)
    headers = _signed_headers(ctx, custom_domain, path)
    header_lines = "".join(f"{name}: {value}\r\n" for name, value in headers.items())
    payload = f"GET {path} HTTP/1.1\r\n{header_lines}Connection: close\r\n\r\n".encode()
    with socket.create_connection(ctx.endpoint_host(gateway_host, 443), timeout=15) as raw:
        with ssl_ctx.wrap_socket(raw, server_hostname=custom_domain) as tls:
            tls.sendall(payload)
            body = b""
            while True:
                chunk = tls.recv(8192)
                if not chunk:
                    break
                body += chunk
    if not body:
        return None, {}, b""
    head, _sep, rest = body.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode(errors="replace")
    status = int(status_line.split(" ")[1])
    headers = dict(
        (k.strip().lower(), v.strip()) for k, v in (ln.split(b":", 1) for ln in lines[1:])
    )
    return status, headers, rest


def _poll_request(ctx, gateway_host, custom_domain, *, cert_path, key_path, accept, timeout_s,
                   interval_s, description):
    """Poll `_request` until accept(status); return its result. OSError/ssl.SSLError during the
    settle window is retried (the dedicated host's DNS record can lag AVAILABLE); RAISES on
    deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            result = _request(
                ctx, gateway_host, custom_domain, cert_path=cert_path, key_path=key_path
            )
        except (OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if accept(result[0]):
                return result
            last = result
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description}: never settled within {timeout_s}s. Last: {last!r}")


@tags(
    "axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
    "dp:endpoint", "plane:data", "requires:dns-baseline",
)
def run(ctx) -> None:
    """A REGIONAL custom domain with mutual TLS serves 200 to a SigV4-signed request presenting a
    trusted client certificate, refuses one signed by another CA with 403 Forbidden, and refuses a
    request carrying no client certificate at the TLS layer.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-mutual-tls.html
    """
    acm = ctx.client("acm")
    apigw = ctx.client("apigateway")
    route53 = ctx.client("route53")
    s3 = ctx.client("s3")

    apex, zone_id = _dns_baseline(route53)
    label = ctx.unique_name("m")
    domain = f"{label}.{apex}"
    assert len(domain) <= 64, (
        f"ACM caps a certificate's first domain name at 64 chars; {domain!r} is {len(domain)}"
    )

    # Bucket for the mTLS truststore.
    bucket = ctx.unique_name("sim2real-behav-mtls-ts-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    trusted_ca, trusted_ca_key = _root_ca(f"ca-{label}")
    trusted_leaf, trusted_leaf_key = _client_leaf(f"ok-{label}", f"ca-{label}", trusted_ca_key)
    other_ca, other_ca_key = _root_ca(f"other-{label}")
    other_leaf, other_leaf_key = _client_leaf(f"bad-{label}", f"other-{label}", other_ca_key)

    put = s3.put_object(Bucket=bucket, Key="truststore.pem", Body=_pem(trusted_ca))
    ctx.on_cleanup(_teardown(
        lambda: s3.delete_object(
            Bucket=bucket, Key="truststore.pem", VersionId=put["VersionId"]
        ),
        "NoSuchKey", "NoSuchBucket",
    ))

    cert_arn = _issue_public_certificate(ctx, acm, route53, zone_id, domain)

    rest = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-mtls-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        disableExecuteApiEndpoint=True,
        tags={"sim2real": CHECK},
    )
    api_id = rest["id"]
    ctx.on_cleanup(_teardown(lambda: apigw.delete_rest_api(restApiId=api_id), "NotFoundException"))
    root_id = next(
        item["id"] for item in apigw.get_resources(restApiId=api_id)["items"] if item["path"] == "/"
    )
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="AWS_IAM")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": f'{{"marker": "{label}"}}'},
    )
    apigw.create_deployment(restApiId=api_id, stageName="prod")

    apigw.create_domain_name(
        domainName=domain,
        endpointConfiguration={"types": ["REGIONAL"]},
        regionalCertificateArn=cert_arn,
        securityPolicy="TLS_1_2",
        mutualTlsAuthentication={
            "truststoreUri": f"s3://{bucket}/truststore.pem",
            "truststoreVersion": put["VersionId"],
        },
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(
        lambda: apigw.delete_domain_name(domainName=domain), "NotFoundException"
    ))
    apigw.create_base_path_mapping(domainName=domain, restApiId=api_id, stage="prod")
    ctx.on_cleanup(_teardown(
        lambda: apigw.delete_base_path_mapping(domainName=domain, basePath="(none)"),
        "NotFoundException",
    ))

    config = _poll_until(
        ctx,
        lambda: _retry_throttle(lambda: apigw.get_domain_name(domainName=domain)),
        lambda cfg: cfg.get("domainNameStatus") == "AVAILABLE",
        timeout_s=300, interval_s=10,
        description=f"the REGIONAL custom domain {domain!r} reaching AVAILABLE",
    )
    gateway_host = config["regionalDomainName"]
    assert gateway_host, f"an AVAILABLE REGIONAL domain must publish a regionalDomainName; got {config!r}"

    tmpdir = tempfile.mkdtemp(prefix="sim2real-behav-mtls-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir))
    trusted_path = _write_pem(tmpdir, "trusted.pem", _pem(trusted_leaf))
    trusted_key_path = _write_pem(tmpdir, "trusted.key", _key_pem(trusted_leaf_key))
    other_path = _write_pem(tmpdir, "other.pem", _pem(other_leaf))
    other_key_path = _write_pem(tmpdir, "other.key", _key_pem(other_leaf_key))

    # (1) Positive control: a client presenting a certificate the truststore trusts is served.
    status, _headers, body = _poll_request(
        ctx, gateway_host, domain, cert_path=trusted_path, key_path=trusted_key_path,
        accept=lambda s: s == 200,
        timeout_s=300, interval_s=10,
        description="a trusted client certificate being served 200",
    )
    assert status == 200, f"a trusted client certificate must be served 200; got {status}"
    assert body == f'{{"marker": "{label}"}}'.encode(), (
        f"a served request must carry this run's fixed mock response; got {body[:200]!r}"
    )

    # (2) No client certificate at all: the refusal is at the TLS layer, never an HTTP response.
    #     Under TLS 1.3 the client-auth decision comes after the handshake, so the server either
    #     resets the connection, tears it down without an alert, closes it with no response, or
    #     sends a certificate-required alert. Any other TLS error is not that refusal.
    try:
        status, _headers, body = _request(ctx, gateway_host, domain)
    except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError):
        # A teardown while the request is still being written surfaces as a broken pipe.
        status, body = None, b""
    except ssl.SSLError as exc:
        assert exc.reason in _NO_CERTIFICATE_ALERTS, (
            f"a request presenting no client certificate must be refused with a reset, a closed "
            f"connection or a certificate-required alert; got {type(exc).__name__} "
            f"reason={exc.reason!r}: {exc}"
        )
        status, body = None, b""
    assert status is None, (
        "a request presenting no client certificate to an mTLS-enabled domain must be "
        f"refused at the TLS layer, but it got status={status!r} body={body[:200]!r}"
    )

    # (3) A certificate signed by another CA: the handshake completes (the client DID present a
    #     certificate), and the gateway refuses the HTTP request itself with 403 Forbidden.
    status, headers, body = _request(
        ctx, gateway_host, domain, cert_path=other_path, key_path=other_key_path
    )
    assert status == 403, (
        f"a client certificate signed by an untrusted CA must be refused with 403; got {status}"
    )
    assert body == b'{"message":"Forbidden"}', (
        f'the refusal must carry the gateway\'s {{"message":"Forbidden"}} envelope; got {body!r}'
    )
    assert headers.get(b"x-amzn-errortype") == b"ForbiddenException", (
        f"the refusal must carry x-amzn-ErrorType: ForbiddenException; got headers {headers!r}"
    )

    # (4) The trusted path still serves after the two refusals — the enforcement did not wedge
    #     the domain.
    #     A request right after the refusals can still be answered 403 for a short while, so
    #     the trusted request is polled back to 200.
    status, _headers, body = _poll_request(
        ctx, gateway_host, domain, cert_path=trusted_path, key_path=trusted_key_path,
        accept=lambda s: s == 200, timeout_s=120, interval_s=10,
        description="the trusted client certificate being served again after the refusals",
    )
    assert status == 200 and body == f'{{"marker": "{label}"}}'.encode(), (
        f"the trusted client certificate must still be served after the refusals; got "
        f"{status} {body[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
