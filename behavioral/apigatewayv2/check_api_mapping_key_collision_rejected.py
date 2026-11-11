"""api-mapping-key-collision-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "api-mapping-key-collision-rejected"
GROUP = "data-plane"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping rejects a second mapping using an ApiMappingKey already mapped on
    the same DomainName with ConflictException, and the original mapping stays intact;
    a distinct key on the same domain still succeeds."""
    apigw = ctx.client("apigatewayv2")

    domain = ctx.unique_name("sim2real-behav-") + ".example.com"
    cert_arn = _import_self_signed_cert(ctx, domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain))

    api1 = _create_basic_http_api(ctx, stage_name="prod1")
    api2 = _create_basic_http_api(ctx, stage_name="prod2")

    shared_key = "shared-key"
    first = apigw.create_api_mapping(
        ApiId=api1["api_id"], DomainName=domain, ApiMappingKey=shared_key, Stage=api1["stage"]
    )
    first_id = first["ApiMappingId"]
    ctx.on_cleanup(lambda: apigw.delete_api_mapping(ApiMappingId=first_id, DomainName=domain))

    code, message = _error_code(
        lambda: apigw.create_api_mapping(
            ApiId=api2["api_id"], DomainName=domain, ApiMappingKey=shared_key, Stage=api2["stage"]
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException for a colliding ApiMappingKey, got {code!r}"
    )
    expected_message = "ApiMapping key already exists for this domain name"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    still_there = apigw.get_api_mapping(ApiMappingId=first_id, DomainName=domain)
    assert still_there["ApiId"] == api1["api_id"], (
        f"original mapping's ApiId changed after the rejected collision: "
        f"expected {api1['api_id']!r}, got {still_there['ApiId']!r}"
    )
    assert still_there["Stage"] == api1["stage"], (
        f"original mapping's Stage changed after the rejected collision: "
        f"expected {api1['stage']!r}, got {still_there['Stage']!r}"
    )

    # Independent side-channel: the rejected call must not have produced a second
    # mapping under a fresh id even though the original mapping looks untouched.
    mappings_after_reject = apigw.get_api_mappings(DomainName=domain)["Items"]
    assert len(mappings_after_reject) == 1, (
        f"expected exactly 1 mapping on the domain after the rejected collision, "
        f"got {len(mappings_after_reject)}: {mappings_after_reject}"
    )

    # Positive control: a distinct mapping key on the same domain succeeds.
    other = apigw.create_api_mapping(
        ApiId=api2["api_id"], DomainName=domain, ApiMappingKey="distinct-key", Stage=api2["stage"]
    )
    other_id = other["ApiMappingId"]
    ctx.on_cleanup(lambda: apigw.delete_api_mapping(ApiMappingId=other_id, DomainName=domain))

    # Terminal read is independent of the mutating call: GetApiMapping, not the
    # CreateApiMapping response.
    other_fetched = apigw.get_api_mapping(ApiMappingId=other_id, DomainName=domain)
    assert other_fetched["ApiId"] == api2["api_id"], (
        f"distinct-key mapping's ApiId mismatch: expected {api2['api_id']!r}, "
        f"got {other_fetched['ApiId']!r}"
    )
    assert other_fetched["ApiMappingKey"] == "distinct-key", (
        f"distinct-key mapping's ApiMappingKey mismatch: expected 'distinct-key', "
        f"got {other_fetched['ApiMappingKey']!r}"
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


def _self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    import subprocess
    import tempfile
    import os as _os

    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    with tempfile.TemporaryDirectory() as d:
        key_path = _os.path.join(d, "key.pem")
        cert_path = _os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "365",
                "-nodes", "-keyout", key_path, "-out", cert_path, "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(key_path, "rb") as f:
            key = f.read()
        with open(cert_path, "rb") as f:
            cert = f.read()
    return cert, key


def _import_self_signed_cert(ctx, domain: str) -> str:
    cert, key = _self_signed_cert(domain)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert, PrivateKey=key, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_unused(acm, arn))
    return arn


def _create_basic_http_api(
    ctx,
    integration_uri="https://example.com/",  # never invoked; a reserved documentation host
    route_key="GET /ping",
    stage_name="prod",
):
    apigw = ctx.client("apigatewayv2")
    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-"),
        ProtocolType="HTTP",
        Tags={"sim2real": CHECK},
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))
    integ = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri=integration_uri,
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )
    apigw.create_route(ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integ['IntegrationId']}")
    apigw.create_stage(
        ApiId=api_id, StageName=stage_name, AutoDeploy=True, Tags={"sim2real": CHECK}
    )
    return {
        "api_id": api_id,
        "integration_id": integ["IntegrationId"],
        "stage": stage_name,
        "api_endpoint": api["ApiEndpoint"],
    }


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


def _retry_throttled(fn):
    """CreateDomainName is rate-limited per account; retry TooManyRequestsException."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(6):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or attempt == 5:
                raise
            time.sleep(5.0 * (attempt + 1))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
