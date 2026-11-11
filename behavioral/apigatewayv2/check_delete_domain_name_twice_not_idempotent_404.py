"""delete-domain-name-twice-not-idempotent-404."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-domain-name-twice-not-idempotent-404"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]
NOT_FOUND_MESSAGE = "Invalid domain name identifier specified"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteDomainName on an already-deleted domain fails NotFoundException instead of
    succeeding again; a fresh domain's first delete succeeds and the domain is actually gone."""
    apigw = ctx.client("apigatewayv2")
    acm = ctx.client("acm")

    # --- negative: delete the same domain twice ---
    domain = f"{ctx.unique_name('sim2real-behav-dom-')}.example.com"
    cert_arn = _request_certificate(ctx, acm, domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
            Tags=TAGS,
        )
    )
    apigw.get_domain_name(DomainName=domain)

    apigw.delete_domain_name(DomainName=domain)  # first delete: succeeds
    # effect: the domain is actually gone now
    code_after_first, msg_after_first = _error_code(lambda: apigw.get_domain_name(DomainName=domain))
    assert code_after_first == "NotFoundException", (
        f"expected domain gone after first delete, got {code_after_first!r}: {msg_after_first!r}"
    )
    assert msg_after_first == NOT_FOUND_MESSAGE, f"unexpected message: {msg_after_first!r}"

    code, msg = _error_code(lambda: apigw.delete_domain_name(DomainName=domain))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}: {msg!r}"
    assert msg == NOT_FOUND_MESSAGE, f"unexpected message: {msg!r}"

    # effect stays absent: still not there, not resurrected by the second call
    code_after_second, msg_after_second = _error_code(lambda: apigw.get_domain_name(DomainName=domain))
    assert code_after_second == "NotFoundException", (
        f"expected domain still gone after second delete, got {code_after_second!r}: {msg_after_second!r}"
    )
    assert msg_after_second == NOT_FOUND_MESSAGE, f"unexpected message: {msg_after_second!r}"

    # --- positive control: a fresh domain's single delete works normally ---
    control_domain = f"{ctx.unique_name('sim2real-behav-dom-')}.example.com"
    control_cert_arn = _request_certificate(ctx, acm, control_domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=control_domain,
            DomainNameConfigurations=[{"CertificateArn": control_cert_arn, "EndpointType": "REGIONAL"}],
            Tags=TAGS,
        )
    )
    apigw.delete_domain_name(DomainName=control_domain)
    control_code, control_msg = _error_code(lambda: apigw.get_domain_name(DomainName=control_domain))
    assert control_code == "NotFoundException", (
        f"expected fresh domain gone after its single delete, got {control_code!r}: {control_msg!r}"
    )
    assert control_msg == NOT_FOUND_MESSAGE, f"unexpected message: {control_msg!r}"


def _error_code(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_throttled(fn, attempts: int = 8, base_delay: float = 20.0):
    """CreateDomainName has a low per-account request rate quota; retry with
    backoff on TooManyRequestsException instead of failing the check on a
    transient throttle."""
    from botocore.exceptions import ClientError

    last_err = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "TooManyRequestsException":
                raise
            last_err = e
            time.sleep(base_delay * (i + 1))
    raise AssertionError(f"CreateDomainName kept throttling after {attempts} retries: {last_err}")


def _request_certificate(ctx, acm, domain: str) -> str:
    """An ACM certificate CreateDomainName can use at once: an imported self-signed cert is ISSUED
    immediately, while a DNS-validated request stays PENDING_VALIDATION without DNS control."""
    cert_pem, key_pem = _self_signed_cert(domain)
    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=TAGS_KV
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying_in_use(acm, cert_arn))
    return cert_arn


def _delete_cert_retrying_in_use(acm, cert_arn, deadline_s=20.0):
    """ACM's InUseBy bookkeeping lags domain deletion, so DeleteCertificate can see
    ResourceInUseException; retry, capped well under the 60s cleanup budget because this check
    registers two such cleanups that run sequentially."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    delay = 3.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 10.0)


def _self_signed_cert(domain: str):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
