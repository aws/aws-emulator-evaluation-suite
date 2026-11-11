"""create-duplicate-domain-name-conflict."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "create-duplicate-domain-name-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    SUCCESS raises, because an over-permissive target accepting a call real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the duplicate CreateDomainName to be rejected, but it SUCCEEDED and returned "
        f"{result!r}"
    )


def _throttle_retry(fn, *, attempts=10, base_delay=15.0, max_delay=35.0):
    """Call fn(), retrying through API Gateway's low account-level control-plane
    throttle. Custom-domain mutations share a bucket that refills roughly once
    every ~30s, so the SDK's own short retries can exhaust and surface
    TooManyRequestsException on legitimate calls. Retry with bucket-sized backoff
    over a generous (~5 min) budget; any other error propagates immediately, and a
    success returns fn()'s result. Re-raises the last throttle if it never clears
    within budget."""
    delay = base_delay
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            last = exc
            if i < attempts - 1:
                time.sleep(min(delay, max_delay))
                delay *= 2
    raise last

def _self_signed_cert(common_name, days_valid=2):
    """Generate a self-signed cert/key pair for ACM import. Returns (cert_pem, key_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem

def _import_cert(ctx, common_name):
    """Import a self-signed cert into ACM (registered for teardown); return its CertificateArn."""
    acm = ctx.client("acm")
    cert_pem, key_pem = _self_signed_cert(common_name)
    arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, arn))
    return arn


def _delete_certificate(acm, arn, timeout_s=300.0):
    """Teardown: the certificate stays in use until the domain-name deletion settles."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(10)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a DomainName that already exists must fail (BadRequestException).

    A duplicate CreateDomainName must not silently succeed or overwrite the existing domain's
    certificate configuration (overly-permissive check).
    """
    ag = ctx.client("apigateway")
    domain = f"{ctx.unique_name('sim2real-behav-domain-')}.example.com"
    cert_arn = _import_cert(ctx, domain)
    created = _throttle_retry(lambda: ag.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: _throttle_retry(lambda: ag.delete_domain_name(domainName=domain)))
    assert created["domainName"] == domain, (
        f"positive control: creating a fresh DomainName {domain!r} did not echo it back, "
        f"got {created.get('domainName')!r}"
    )

    other_cert_arn = _import_cert(ctx, domain)
    code, message = _error(
        lambda: _throttle_retry(lambda: ag.create_domain_name(
            domainName=domain,
            regionalCertificateArn=other_cert_arn,
            endpointConfiguration={"types": ["REGIONAL"]},
        ))
    )
    # _throttle_retry waits out the ~1-req/30s bucket, so the terminal refusal is graded.
    assert code == "BadRequestException", (
        f"expected BadRequestException creating a DomainName that already exists, got {code}"
    )
    assert message == "The domain name you provided already exists.", (
        f"unexpected BadRequestException message {message!r}"
    )

    unchanged = ag.get_domain_name(domainName=domain)
    assert unchanged["regionalCertificateArn"] == cert_arn, (
        "the rejected duplicate CreateDomainName must not have overwritten the existing "
        f"certificate, got {unchanged.get('regionalCertificateArn')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
