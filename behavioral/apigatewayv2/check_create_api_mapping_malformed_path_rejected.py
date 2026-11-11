"""create-api-mapping-malformed-path-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-mapping-malformed-path-rejected"
GROUP = "negative-classes"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-apigwv2"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping with an ApiMappingKey that starts with '/' is rejected with
    BadRequestException, and never persists; a well-formed key still maps successfully."""
    apigwv2 = ctx.client("apigatewayv2")
    domain_name = _create_domain_name(ctx)
    api_id = _create_http_api(ctx)
    _create_stage(ctx, api_id, "dev")

    code, message = _error_code(
        lambda: apigwv2.create_api_mapping(
            DomainName=domain_name, ApiId=api_id, Stage="dev", ApiMappingKey="/bad-leading-slash"
        )
    )
    assert code == "BadRequestException", (
        f"a leading-slash ApiMappingKey should be rejected with BadRequestException, got {code!r}"
    )
    expected_message = "API mapping key should not start with a '/' or have consecutive '/'s."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    listing = apigwv2.get_api_mappings(DomainName=domain_name)["Items"]
    assert not any(m.get("ApiMappingKey") == "/bad-leading-slash" for m in listing), (
        f"the rejected leading-slash key must not appear in GetApiMappings, got {listing!r}"
    )

    # positive control: a syntactically valid key maps successfully.
    good = apigwv2.create_api_mapping(
        DomainName=domain_name, ApiId=api_id, Stage="dev", ApiMappingKey="good-path"
    )
    ctx.on_cleanup(
        lambda: apigwv2.delete_api_mapping(DomainName=domain_name, ApiMappingId=good["ApiMappingId"])
    )
    fetched = apigwv2.get_api_mapping(DomainName=domain_name, ApiMappingId=good["ApiMappingId"])
    assert fetched["ApiMappingKey"] == "good-path", (
        f"a syntactically valid key must map and round-trip via GetApiMapping, "
        f"got ApiMappingKey={fetched.get('ApiMappingKey')!r}"
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


def _import_self_signed_cert(ctx, common_name):
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem, Tags=[
        {"Key": k, "Value": v} for k, v in TAGS.items()
    ])
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_unused(acm, cert_arn))
    return cert_arn


def _delete_cert_when_unused(acm, cert_arn):
    """DeleteCertificate 400s with ResourceInUseException for a window after the custom domain
    name that referenced it is deleted, while ACM propagates the disassociation; retry through
    that window instead of leaking the cert."""
    for attempt in range(10):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or attempt == 9:
                raise
            time.sleep(3)


def _create_domain_name(ctx):
    apigwv2 = ctx.client("apigatewayv2")
    label = ctx.unique_name("sim2real-apigwv2-").lower().replace("_", "-")
    domain_name = f"{label}.example.com"
    cert_arn = _import_self_signed_cert(ctx, domain_name)
    apigwv2.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[
            {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
        ],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: apigwv2.delete_domain_name(DomainName=domain_name))
    return domain_name


def _create_http_api(ctx):
    apigwv2 = ctx.client("apigatewayv2")
    resp = apigwv2.create_api(
        Name=ctx.unique_name("sim2real-api-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id = resp["ApiId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api(ApiId=api_id))
    return api_id


def _create_stage(ctx, api_id, stage_name):
    apigwv2 = ctx.client("apigatewayv2")
    apigwv2.create_stage(ApiId=api_id, StageName=stage_name, Tags=TAGS)
    ctx.on_cleanup(lambda: apigwv2.delete_stage(ApiId=api_id, StageName=stage_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
