"""reject-domain-name-access-association-without-pending-fails."""
from __future__ import annotations

import datetime
import uuid
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "reject-domain-name-access-association-without-pending-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectDomainNameAccessAssociation applies only to an association pending from another
    account: for one that does not exist on the check's own domain name it fails with
    BadRequestException, leaves the domain intact and creates no association."""
    apigw = ctx.client("apigateway")
    domain = _create_domain_name_best_effort(ctx)
    domain_arn = apigw.get_domain_name(domainName=domain)["domainNameArn"]

    fake_vpce = "vpce-" + uuid.uuid4().hex[:17]
    fake_assoc_arn = (
        f"arn:aws:apigateway:{ctx.region}::/domainnameaccessassociations/domainname/"
        f"{domain}+missing/vpcesource/{fake_vpce}"
    )

    code, message = _error(
        lambda: apigw.reject_domain_name_access_association(
            domainNameAccessAssociationArn=fake_assoc_arn, domainNameArn=domain_arn
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException rejecting a non-pending/nonexistent access "
        f"association, got {code!r}"
    )
    assert message == "Invalid domain name ARN specified.", f"unexpected message: {message!r}"

    # the domain name itself must be unaffected by the rejected/failed call
    still_there = apigw.get_domain_name(domainName=domain)
    assert still_there["domainName"] == domain

    # The rejected call must not have created an association visible on an independent read.
    associations = apigw.get_domain_name_access_associations().get("items", [])
    assert all(a.get("domainNameAccessAssociationArn") != fake_assoc_arn for a in associations), (
        f"a rejected RejectDomainNameAccessAssociation call must not create an "
        f"association, found {fake_assoc_arn!r} in {associations!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _retry_throttled(fn, attempts: int = 6, base_delay: float = 5.0):
    """CreateDomainName is subject to a low, account-wide APIGW rate limit that
    botocore's own built-in retry budget (5 attempts, short backoff) is not
    always enough to ride out. Retry with a longer exponential backoff on
    TooManyRequestsException before giving up."""
    import random
    import time as _time

    from botocore.exceptions import ClientError

    last_exc: ClientError | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            last_exc = e
            if attempt < attempts - 1:
                _time.sleep(base_delay * (2**attempt) + random.uniform(0, base_delay))
    raise last_exc


def _create_domain_name_best_effort(ctx) -> str:
    apigw = ctx.client("apigateway")
    domain = (ctx.unique_name("sim2real-rej-") + ".example.com").lower()

    from botocore.exceptions import ClientError

    try:
        _retry_throttled(
            lambda: apigw.create_domain_name(domainName=domain, tags={"sim2real": CHECK})
        )
        ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain))
        return domain
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "BadRequestException":
            raise

    cert_arn = _import_self_signed_cert(ctx, domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            domainName=domain,
            regionalCertificateArn=cert_arn,
            endpointConfiguration={"types": ["REGIONAL"]},
            tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain))
    return domain


def _import_self_signed_cert(ctx, common_name: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

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
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, cert_arn))
    return cert_arn


def _delete_certificate_when_released(acm, cert_arn: str, timeout_s: float = 300.0) -> None:
    """ACM keeps a certificate in use for a while after its custom domain is deleted, so retry
    ResourceInUseException within a bounded window; any other error propagates."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "ResourceInUseException":
                raise
            if _time.monotonic() >= deadline:
                raise
            _time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
