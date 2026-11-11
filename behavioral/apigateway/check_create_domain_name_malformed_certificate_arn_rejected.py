"""create-domain-name-malformed-certificate-arn-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "create-domain-name-malformed-certificate-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]

_CLEANUP_S = 840.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainName with a certificateArn that is not a well-formed ACM ARN is rejected as malformed,
    unlike the "certificate not provided" error a well-formed absent certificate gets, and creates no
    domain, while a valid ACM certificate is accepted."""
    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")

    # positive control: a well-formed regionalCertificateArn succeeds, so the rejections below
    # are scoped to the malformed/missing certificate reference and are not just "this target
    # refuses every CreateDomainName".
    good_domain = ctx.unique_name("sim2real-behav-gooddom-").lower() + ".example.com"
    good_cert_arn = _import_cert(ctx, acm, good_domain)
    created = apigw.create_domain_name(
        domainName=good_domain,
        regionalCertificateArn=good_cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, good_domain))
    assert created["domainName"] == good_domain, (
        f"expected the positive control to create {good_domain!r}, got {created.get('domainName')!r}"
    )

    bad_domain = ctx.unique_name("sim2real-behav-baddom-").lower() + ".example.com"
    malformed_code, malformed_message = _error(
        lambda: apigw.create_domain_name(
            domainName=bad_domain,
            certificateArn="not-a-well-formed-acm-arn",
        )
    )
    assert malformed_code == "BadRequestException", f"expected BadRequestException, got {malformed_code}"
    assert malformed_message == "Invalid ARN specified in the request", f"unexpected BadRequestException message {malformed_message!r}"

    # effect-absent: the DomainName resource was never created.
    not_found_code, not_found_message = _error(lambda: apigw.get_domain_name(domainName=bad_domain))
    assert not_found_code == "NotFoundException", f"expected NotFoundException, got {not_found_code}"
    assert not_found_message == "Invalid domain name identifier specified", f"unexpected NotFoundException message {not_found_message!r}"

    # distinctness control: an EDGE domain request with the certificate field omitted entirely
    # is rejected too, but with a message that must actually differ from the malformed-ARN
    # message above -- proving the malformed-ARN rejection is a format check on the ARN itself,
    # and not just "any missing/invalid cert fails the same generic way".
    no_cert_domain = ctx.unique_name("sim2real-behav-nocertdom-").lower() + ".example.com"
    no_cert_code, no_cert_message = _error(lambda: apigw.create_domain_name(domainName=no_cert_domain))
    assert no_cert_code == "BadRequestException", f"expected BadRequestException, got {no_cert_code}"
    assert no_cert_message == "A certificate was not provided for the endpoint type EDGE.", f"unexpected BadRequestException message {no_cert_message!r}"
    assert no_cert_message != malformed_message, (
        "expected the missing-certificate rejection message to differ from the malformed-ARN "
        f"rejection message, got the same message {no_cert_message!r} for both"
    )

    # effect-absent for the second rejection too: an independent read, not just the mutating
    # call's own response.
    no_cert_not_found, no_cert_not_found_message = _error(lambda: apigw.get_domain_name(domainName=no_cert_domain))
    assert no_cert_not_found == "NotFoundException", (
        f"expected NotFoundException, got {no_cert_not_found}"
    )
    assert no_cert_not_found_message == "Invalid domain name identifier specified", (
        f"unexpected NotFoundException message {no_cert_not_found_message!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _self_signed_cert_pem(common_name: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
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


def _import_cert(ctx, acm, common_name: str) -> str:
    cert_pem, key_pem = _self_signed_cert_pem(common_name)
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert(acm, cert_arn))
    return cert_arn


def _delete_cert(acm, cert_arn: str) -> None:
    """Teardown: ACM answers ResourceInUseException until API Gateway releases a deleted domain's
    certificate, so retry it every 2 s to the deadline; not-found is done, anything else raises."""
    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_domain(apigw, domain: str) -> None:
    _safe(lambda: apigw.delete_domain_name(domainName=domain))


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
