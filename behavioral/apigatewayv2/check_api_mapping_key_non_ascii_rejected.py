"""api-mapping-key-non-ascii-rejected."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-mapping-key-non-ascii-rejected"
GROUP = "representation"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-map"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping rejects an ApiMappingKey containing non-ASCII (unicode) characters
    with BadRequestException, creates no mapping, and a same-domain ASCII mapping key still
    round-trips byte-identical via GetApiMapping (positive control)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    domain_name = f"{ctx.unique_name('sim2real-map-')}.example.com"
    cert_arn = _import_self_signed_cert(ctx, domain_name)
    apigw = ctx.client("apigatewayv2")
    apigw.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_domain_name(DomainName=domain_name)))

    api_id = apigw.create_api(
        Name=ctx.unique_name("sim2real-api-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_api(ApiId=api_id)))
    stage_name = "prod"
    apigw.create_stage(ApiId=api_id, StageName=stage_name, Tags=TAGS)
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_stage(ApiId=api_id, StageName=stage_name)))

    # Break exactly one thing: a mapping key containing a non-ASCII unicode character.
    unicode_key = "caf\u00e9"

    def _attempt():
        apigw.create_api_mapping(
            ApiId=api_id, DomainName=domain_name, Stage=stage_name, ApiMappingKey=unicode_key
        )

    code, message = _error_code(_attempt)
    assert code == "BadRequestException", code
    expected_message = "An API mapping key may contain only letters, numbers and one of $-_.+!*'(), characters."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    items = apigw.get_api_mappings(DomainName=domain_name)["Items"]
    assert all(item.get("ApiMappingKey") != unicode_key for item in items), items
    assert len(items) == 0, items

    # Positive control: an ASCII-only mapping key (letters, digits, dot) round-trips exactly.
    ascii_key = "v1.2"
    created = apigw.create_api_mapping(
        ApiId=api_id, DomainName=domain_name, Stage=stage_name, ApiMappingKey=ascii_key
    )
    mapping_id = created["ApiMappingId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name))
    )
    fetched = apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name)
    assert fetched["ApiMappingKey"] == ascii_key, fetched["ApiMappingKey"]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
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


def _generate_self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        cert_path = Path(d) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "2", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        return cert_path.read_bytes(), key_path.read_bytes()


def _import_self_signed_cert(ctx, common_name: str) -> str:
    acm = ctx.client("acm")
    cert_pem, key_pem = _generate_self_signed_cert(common_name)
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem, Tags=TAGS_KV)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
    return cert_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
