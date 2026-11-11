"""api-mapping-path-special-chars-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-mapping-path-special-chars-round-trip"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ApiMappingKey with URL-safe special characters and multiple path segments is
    persisted and returned byte-identical by GetApiMapping."""
    apigw = ctx.client("apigatewayv2")

    domain = ctx.unique_name("sim2real-behav-") + ".example.com"
    cert_arn = _import_self_signed_cert(ctx, domain)
    _retry_throttled(ctx, lambda: apigw.create_domain_name(
        DomainName=domain,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
    ))
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain))

    api = _create_basic_http_api(ctx)

    mapping_key = "release-2024.v1/build_42!final(copy)"
    mapping = apigw.create_api_mapping(
        ApiId=api["api_id"], DomainName=domain, ApiMappingKey=mapping_key, Stage=api["stage"]
    )
    mapping_id = mapping["ApiMappingId"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain)))

    assert mapping["ApiMappingKey"] == mapping_key, mapping.get("ApiMappingKey")

    got = apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
    assert got["ApiMappingKey"] == mapping_key, got.get("ApiMappingKey")
    assert got["ApiId"] == api["api_id"], got.get("ApiId")
    assert got["Stage"] == api["stage"], got.get("Stage")

    # The mapping key survived the round trip; now prove a delete of it is real:
    # the id becomes genuinely unusable, not merely absent from one read path.
    apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain)

    code, message = _error_code(lambda: apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain))
    assert code == "NotFoundException", f"expected NotFoundException reading a deleted mapping, got {code}"
    expected_message = f"Unable to find ApiMapping with ID {mapping_id}"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    listing = apigw.get_api_mappings(DomainName=domain)["Items"]
    assert not any(m.get("ApiMappingId") == mapping_id for m in listing), listing

    code, message = _error_code(lambda: apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain))
    assert code == "NotFoundException", f"expected NotFoundException deleting an already-deleted mapping, got {code}"
    expected_message = f"Unable to find ApiMapping with ID {mapping_id}"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


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
    resp = acm.import_certificate(Certificate=cert, PrivateKey=key)
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
    api = apigw.create_api(Name=ctx.unique_name("sim2real-behav-"), ProtocolType="HTTP")
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
    apigw.create_stage(ApiId=api_id, StageName=stage_name, AutoDeploy=True)
    return {
        "api_id": api_id,
        "integration_id": integ["IntegrationId"],
        "stage": stage_name,
        "api_endpoint": api["ApiEndpoint"],
    }


# budget.cleanup_timeout for behavioral/apigatewayv2
_CLEANUP_S = 900.0
# CreateDomainName is rate limited account-wide; how long its throttle is waited out.
_THROTTLE_WAIT_S = 120.0


def _retry_throttled(ctx, fn):
    """Call fn, retrying TooManyRequestsException every 2 s to a deadline capped by ctx.time_left()."""
    import time

    left = ctx.time_left()
    deadline = time.monotonic() + (_THROTTLE_WAIT_S if left is None else min(_THROTTLE_WAIT_S, left))
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_cert_when_unused(acm, cert_arn) -> None:
    """DeleteCertificate returns ResourceInUseException for a window after the custom domain
    name that referenced the cert is deleted, while ACM propagates the disassociation; retry
    every 2 s up to the cleanup budget so the cert is not leaked."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
