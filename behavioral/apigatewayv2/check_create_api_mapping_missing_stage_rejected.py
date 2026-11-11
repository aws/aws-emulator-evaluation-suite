"""create-api-mapping-missing-stage-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-api-mapping-missing-stage-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping with an empty Stage fails BadRequestException and creates no mapping; a
    mapping with the real "$default" stage succeeds and is visible via GetApiMappings."""
    apigw = ctx.client("apigatewayv2")
    acm = ctx.client("acm")

    api_id = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-api-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    apigw.create_stage(ApiId=api_id, StageName="$default", Tags=TAGS)

    domain = f"{ctx.unique_name('sim2real-behav-dom-')}.example.com"
    cert_arn = _request_certificate(ctx, acm, domain)
    apigw.create_domain_name(
        DomainName=domain,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain))

    # --- negative: Stage="" is present but not a usable stage reference ---
    code, message = _error_code(
        lambda: apigw.create_api_mapping(ApiId=api_id, DomainName=domain, Stage="")
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected_message = "Invalid stage identifier specified"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # effect absent: no mapping was created on the domain
    items = apigw.get_api_mappings(DomainName=domain)["Items"]
    assert items == [], f"expected no api mappings to exist, found {items!r}"

    # --- positive control: a real stage reference is accepted ---
    mapping = apigw.create_api_mapping(ApiId=api_id, DomainName=domain, Stage="$default")
    ctx.on_cleanup(
        lambda mid=mapping["ApiMappingId"]: apigw.delete_api_mapping(
            ApiMappingId=mid, DomainName=domain
        )
    )
    items_after = apigw.get_api_mappings(DomainName=domain)["Items"]
    assert any(i["ApiMappingId"] == mapping["ApiMappingId"] for i in items_after), (
        f"expected mapping {mapping['ApiMappingId']!r} to be visible, found {items_after!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises.
    Throttling is retried."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, error.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError("unreachable: the loop always returns or raises")


def _request_certificate(ctx, acm, domain: str) -> str:
    """An ACM certificate CreateDomainName can use at once: an imported self-signed cert is ISSUED
    immediately, while a DNS-validated request stays PENDING_VALIDATION without DNS control."""
    cert_pem, key_pem = _self_signed_cert(domain)
    cert_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_retrying(acm, cert_arn))
    return cert_arn


def _delete_certificate_retrying(acm, cert_arn: str) -> None:
    """DeleteCertificate can return ResourceInUseException for a few seconds after DeleteDomainName;
    retry through it, bounded well under the 60s cleanup budget since delete_api runs afterward."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(5):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or attempt == 4:
                raise RuntimeError(f"certificate {cert_arn!r} not deleted: {code}") from e
            time.sleep(3)


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
