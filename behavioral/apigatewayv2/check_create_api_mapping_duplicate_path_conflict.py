"""create-api-mapping-duplicate-path-conflict."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-api-mapping-duplicate-path-conflict"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second ApiMapping at an identical path fails ConflictException, leaving the first intact;
    after deleting the original the same call succeeds, the dead id fails not-found, and a
    different path on the same domain succeeds."""
    apigw = ctx.client("apigatewayv2")

    domain = f"{ctx.unique_name('sim2real-behav-')}.example.com"
    _create_domain(ctx, apigw, domain)


    api1 = _create_api(ctx, apigw)
    api2 = _create_api(ctx, apigw)
    stage1, stage2 = "s1", "s2"
    apigw.create_stage(ApiId=api1, StageName=stage1)
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: apigw.delete_stage(ApiId=api1, StageName=stage1))
    )
    apigw.create_stage(ApiId=api2, StageName=stage2)
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: apigw.delete_stage(ApiId=api2, StageName=stage2))
    )

    first = apigw.create_api_mapping(
        ApiId=api1, DomainName=domain, Stage=stage1, ApiMappingKey="dup"
    )
    mapping1_id = first["ApiMappingId"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: apigw.delete_api_mapping(ApiMappingId=mapping1_id, DomainName=domain)
        )
    )

    code, message = _error_code(
        lambda: apigw.create_api_mapping(
            ApiId=api2, DomainName=domain, Stage=stage2, ApiMappingKey="dup"
        )
    )
    assert code == "ConflictException"
    expected_message = "ApiMapping key already exists for this domain name"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # effect absent: the original mapping is untouched, and no second mapping was created
    got1 = apigw.get_api_mapping(ApiMappingId=mapping1_id, DomainName=domain)
    assert got1["ApiId"] == api1 and got1["Stage"] == stage1
    all_mappings = apigw.get_api_mappings(DomainName=domain)["Items"]
    assert len([m for m in all_mappings if m["ApiMappingKey"] == "dup"]) == 1

    # restore: delete the mapping holding the key, then the identical call now succeeds
    apigw.delete_api_mapping(ApiMappingId=mapping1_id, DomainName=domain)
    gone_code, gone_message = _error_code(
        lambda: apigw.get_api_mapping(ApiMappingId=mapping1_id, DomainName=domain)
    )
    assert gone_code == "NotFoundException"
    expected_message = f"Unable to find ApiMapping with ID {mapping1_id}"
    assert gone_message == expected_message, (
        f"expected the exact message {expected_message!r}, got {gone_message!r}"
    )
    dead_mutation_code, dead_mutation_message = _error_code(
        lambda: apigw.update_api_mapping(
            ApiId=api1,
            ApiMappingId=mapping1_id,
            DomainName=domain,
            ApiMappingKey="whatever",
        )
    )
    assert dead_mutation_code == "NotFoundException"
    expected_message = f"Unable to find ApiMapping with ID {mapping1_id}"
    assert dead_mutation_message == expected_message, (
        f"expected the exact message {expected_message!r}, got {dead_mutation_message!r}"
    )

    restored = apigw.create_api_mapping(
        ApiId=api2, DomainName=domain, Stage=stage2, ApiMappingKey="dup"
    )
    restored_id = restored["ApiMappingId"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: apigw.delete_api_mapping(ApiMappingId=restored_id, DomainName=domain)
        )
    )
    assert restored["ApiId"] == api2 and restored["Stage"] == stage2

    # positive control: a different mapping key on the same domain succeeds
    second = apigw.create_api_mapping(
        ApiId=api2, DomainName=domain, Stage=stage2, ApiMappingKey="other"
    )
    mapping2_id = second["ApiMappingId"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: apigw.delete_api_mapping(ApiMappingId=mapping2_id, DomainName=domain)
        )
    )
    assert apigw.get_api_mapping(ApiMappingId=mapping2_id, DomainName=domain)["ApiId"] == api2


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


def _ignore_client_error(fn) -> None:
    """Best-effort cleanup call: a ClientError (typically not-found) is swallowed."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


def _create_api(ctx, apigw):
    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-api-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: apigw.delete_api(ApiId=api_id)))
    return api_id


def _create_domain(ctx, apigw, domain):
    acm = ctx.client("acm")
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
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}
            ],
            Tags=TAGS,
        )
    )
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: apigw.delete_domain_name(DomainName=domain)))
    return created


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

