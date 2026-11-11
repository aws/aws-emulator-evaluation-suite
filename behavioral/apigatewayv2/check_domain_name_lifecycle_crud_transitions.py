"""domain-name-lifecycle-crud-transitions."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-name-lifecycle-crud-transitions"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomainName -> GetDomainName reflects it -> UpdateDomainName changes RoutingMode ->
    DeleteDomainName -> subsequent GetDomainName returns NotFoundException."""
    apigw = ctx.client("apigatewayv2")
    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2real-behav-')}.example.com"

    cert_pem, key_pem = _self_signed_cert(domain)
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)[
        "CertificateArn"
    ]
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    )

    created = _retrying(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            Tags={"phase": "created"},
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}
            ],
        )
    )

    assert created["DomainName"] == domain, (
        f"expected CreateDomainName to echo {domain!r}, got {created['DomainName']!r}"
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: apigw.delete_domain_name(DomainName=domain))
    )

    got = apigw.get_domain_name(DomainName=domain)
    assert got["DomainName"] == domain, (
        f"expected GetDomainName to return {domain!r}, got {got['DomainName']!r}"
    )
    assert got["Tags"] == {"phase": "created"}, (
        f"expected Tags {{'phase': 'created'}}, got {got['Tags']!r}"
    )

    updated = apigw.update_domain_name(
        DomainName=domain, RoutingMode="ROUTING_RULE_THEN_API_MAPPING"
    )
    assert updated["RoutingMode"] == "ROUTING_RULE_THEN_API_MAPPING", (
        f"expected UpdateDomainName to return RoutingMode "
        f"'ROUTING_RULE_THEN_API_MAPPING', got {updated['RoutingMode']!r}"
    )

    got2 = apigw.get_domain_name(DomainName=domain)
    assert got2["RoutingMode"] == "ROUTING_RULE_THEN_API_MAPPING", (
        f"expected GetDomainName after update to report RoutingMode "
        f"'ROUTING_RULE_THEN_API_MAPPING', got {got2['RoutingMode']!r}"
    )
    # unrelated attributes must have survived the partial update untouched
    assert got2["Tags"] == {"phase": "created"}, (
        f"expected Tags to survive the RoutingMode-only update unchanged, got {got2['Tags']!r}"
    )

    apigw.delete_domain_name(DomainName=domain)

    code, message = _error_code(lambda: apigw.get_domain_name(DomainName=domain))
    assert code == "NotFoundException", (
        f"expected GetDomainName on a deleted domain to raise NotFoundException, got {code!r}: {message!r}"
    )
    assert message == NOT_FOUND_MESSAGE, f"unexpected GetDomainName message: {message!r}"

    update_code, update_message = _error_code(
        lambda: apigw.update_domain_name(
            DomainName=domain, RoutingMode="ROUTING_RULE_THEN_API_MAPPING"
        )
    )
    assert update_code == "NotFoundException", (
        f"expected UpdateDomainName on a deleted domain to raise NotFoundException, "
        f"got {update_code!r}: {update_message!r}"
    )
    assert update_message == NOT_FOUND_MESSAGE, f"unexpected UpdateDomainName message: {update_message!r}"


NOT_FOUND_MESSAGE = "Invalid domain name identifier specified"


def _error_code(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_client_error(fn) -> None:
    """Best-effort teardown: a resource that is already gone is fine."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


def _self_signed_cert(domain):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
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


def _retrying(fn, *, retries=6, base_delay=3.0):
    import time

    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return fn()
        except ClientError as e:
            if (
                e.response["Error"]["Code"] == "TooManyRequestsException"
                and attempt < retries - 1
            ):
                time.sleep(base_delay * (attempt + 1))
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


