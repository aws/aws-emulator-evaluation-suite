"""api-mapping-duplicate-path-rejected."""
from __future__ import annotations

import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-mapping-duplicate-path-rejected"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-apigwv2-dup"}
TAGS_ACM = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping at a path already mapped on the domain fails ConflictException and leaves
    the mapping set unchanged; a sibling mapping at a different path still succeeds."""
    domain_name = ctx.unique_name("sim2real-apigwv2-dup-") + ".example.com"
    cert_pem, key_pem = _generate_self_signed_cert(ctx, domain_name)
    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem.encode(), PrivateKey=key_pem.encode(), Tags=TAGS_ACM
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_unused(acm, cert_arn))

    apigwv2 = ctx.client("apigatewayv2")
    apigwv2.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[
            {
                "EndpointType": "REGIONAL",
                "CertificateArn": cert_arn,
                "SecurityPolicy": "TLS_1_2",
            }
        ],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: apigwv2.delete_domain_name(DomainName=domain_name))

    api1 = apigwv2.create_api(
        Name=ctx.unique_name("sim2real-apigwv2-dup-api1-"), ProtocolType="HTTP", Tags=TAGS
    )
    api1_id = api1["ApiId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api(ApiId=api1_id))
    apigwv2.create_stage(ApiId=api1_id, StageName="$default", AutoDeploy=True)

    api2 = apigwv2.create_api(
        Name=ctx.unique_name("sim2real-apigwv2-dup-api2-"), ProtocolType="HTTP", Tags=TAGS
    )
    api2_id = api2["ApiId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api(ApiId=api2_id))
    apigwv2.create_stage(ApiId=api2_id, StageName="$default", AutoDeploy=True)

    mapping1 = apigwv2.create_api_mapping(
        ApiId=api1_id, DomainName=domain_name, Stage="$default", ApiMappingKey="shared"
    )
    mapping1_id = mapping1["ApiMappingId"]
    ctx.on_cleanup(
        lambda: apigwv2.delete_api_mapping(ApiMappingId=mapping1_id, DomainName=domain_name)
    )

    # Break exactly one thing: a second mapping at the SAME path ("shared") on
    # the SAME domain, pointing at a different API.
    code, message = _error_code(
        lambda: apigwv2.create_api_mapping(
            ApiId=api2_id, DomainName=domain_name, Stage="$default", ApiMappingKey="shared"
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException for a duplicate ApiMappingKey on the same domain, got {code!r}"
    )
    expected_message = "ApiMapping key already exists for this domain name"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # The rejected mapping must not exist: exactly one mapping on the domain,
    # still pointing at api1.
    items = apigwv2.get_api_mappings(DomainName=domain_name)["Items"]
    assert len(items) == 1, (
        f"expected exactly one mapping on the domain after the rejected duplicate, got {items!r}"
    )
    assert items[0]["ApiId"] == api1_id, (
        f"expected the surviving mapping to still point at api1 ({api1_id!r}), got {items[0]!r}"
    )
    assert items[0]["ApiMappingKey"] == "shared", (
        f"expected the surviving mapping's key to still be 'shared', got {items[0]!r}"
    )

    # Positive control, same file: a mapping at a DIFFERENT path still succeeds.
    mapping2 = apigwv2.create_api_mapping(
        ApiId=api2_id, DomainName=domain_name, Stage="$default", ApiMappingKey="other"
    )
    mapping2_id = mapping2["ApiMappingId"]
    ctx.on_cleanup(
        lambda: apigwv2.delete_api_mapping(ApiMappingId=mapping2_id, DomainName=domain_name)
    )
    fetched2 = apigwv2.get_api_mapping(ApiMappingId=mapping2_id, DomainName=domain_name)
    assert fetched2["ApiId"] == api2_id, (
        f"expected the positive-control mapping to point at api2 ({api2_id!r}), got {fetched2!r}"
    )
    assert fetched2["ApiMappingKey"] == "other", (
        f"expected the positive-control mapping's key to be 'other', got {fetched2!r}"
    )

    # The original mapping is still intact and unaffected by the rejected attempt.
    fetched1 = apigwv2.get_api_mapping(ApiMappingId=mapping1_id, DomainName=domain_name)
    assert fetched1["ApiId"] == api1_id, (
        f"expected the original mapping to still point at api1 ({api1_id!r}), got {fetched1!r}"
    )
    assert fetched1["ApiMappingKey"] == "shared", (
        f"expected the original mapping's key to still be 'shared', got {fetched1!r}"
    )


def _generate_self_signed_cert(ctx, common_name: str) -> tuple[str, str]:
    """Mint a self-signed cert for ACM ImportCertificate: it is ISSUED immediately, as
    CreateDomainName requires; a DNS-validated request never issues for a domain we don't own."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    with tempfile.TemporaryDirectory() as td:
        key_path = f"{td}/key.pem"
        cert_path = f"{td}/cert.pem"
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "30", "-nodes", "-subj", f"/CN={common_name}",
        ]
        subprocess.run(
            cmd, check=True, capture_output=True, env=ctx.subprocess_env(), timeout=30
        )
        with open(cert_path) as fh:
            cert_pem = fh.read()
        with open(key_path) as fh:
            key_pem = fh.read()
    return cert_pem, key_pem


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


def _delete_cert_when_unused(acm, cert_arn) -> None:
    """DeleteCertificate returns ResourceInUseException for a window after the custom domain
    name that referenced the cert is deleted, while ACM propagates the disassociation; retry
    through that window instead of leaking the cert."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(10):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or attempt == 9:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
