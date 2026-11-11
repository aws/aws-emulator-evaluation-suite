"""api-mapping-lifecycle-crud."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "api-mapping-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping under a domain -> GetApiMapping returns it -> UpdateApiMapping changes
    stage/path -> DeleteApiMapping -> GetApiMapping returns NotFoundException."""
    apigw = ctx.client("apigatewayv2")

    domain = f"{ctx.unique_name('sim2real-behav-')}.example.com"
    _create_domain(ctx, apigw, domain)

    api_id = _create_api(ctx, apigw)
    stage_a, stage_b = "stagea", "stageb"
    apigw.create_stage(ApiId=api_id, StageName=stage_a)
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: apigw.delete_stage(ApiId=api_id, StageName=stage_a))
    )
    apigw.create_stage(ApiId=api_id, StageName=stage_b)
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: apigw.delete_stage(ApiId=api_id, StageName=stage_b))
    )

    created = apigw.create_api_mapping(
        ApiId=api_id, DomainName=domain, Stage=stage_a, ApiMappingKey="v1"
    )
    mapping_id = created["ApiMappingId"]
    assert created["Stage"] == stage_a and created["ApiMappingKey"] == "v1", (
        f"CreateApiMapping did not echo the requested stage/key: {created!r}"
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
        )
    )

    got = apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
    assert got["Stage"] == stage_a and got["ApiMappingKey"] == "v1" and got["ApiId"] == api_id, (
        f"independent GetApiMapping after create did not reflect it: {got!r}"
    )

    updated = apigw.update_api_mapping(
        ApiMappingId=mapping_id,
        DomainName=domain,
        ApiId=api_id,
        Stage=stage_b,
        ApiMappingKey="v2",
    )

    assert updated["Stage"] == stage_b and updated["ApiMappingKey"] == "v2", (
        f"UpdateApiMapping did not echo the new stage/key: {updated!r}"
    )

    got2 = apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
    assert got2["Stage"] == stage_b and got2["ApiMappingKey"] == "v2", (
        f"independent GetApiMapping after update did not reflect the new stage/key: {got2!r}"
    )

    apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain)

    code, message = _error_code(
        lambda: apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
    )
    assert code == "NotFoundException", (
        f"GetApiMapping after delete returned {code!r}, expected NotFoundException"
    )
    expected_message = f"Unable to find ApiMapping with ID {mapping_id}"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
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
