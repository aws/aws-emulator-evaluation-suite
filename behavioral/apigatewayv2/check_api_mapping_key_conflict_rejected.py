"""api-mapping-key-conflict-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-mapping-key-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-mc"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping with a mapping key already used on the domain is rejected with ConflictException,
    the original mapping is left untouched, and a mapping with a distinct key still succeeds (positive control)."""
    apigw = ctx.client("apigatewayv2")

    api_id = apigw.create_api(
        Name=ctx.unique_name("sim2real-mc-api-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_api(ApiId=api_id)))

    domain = _domain_name(ctx, "sim2real-mc-dn")
    cert_arn = _self_signed_cert_arn(ctx, domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
            Tags=TAGS,
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=domain)))

    stage_name = "prod"
    apigw.create_stage(ApiId=api_id, StageName=stage_name)

    original = apigw.create_api_mapping(
        ApiId=api_id, DomainName=domain, Stage=stage_name, ApiMappingKey="dup"
    )
    original_id = original["ApiMappingId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_api_mapping(ApiMappingId=original_id, DomainName=domain)
        )
    )

    # Break exactly one thing: create a second mapping on the same domain with the same key.
    code, message = _error_code(
        lambda: apigw.create_api_mapping(
            ApiId=api_id, DomainName=domain, Stage=stage_name, ApiMappingKey="dup"
        )
    )
    assert code == "ConflictException", code
    expected_message = "ApiMapping key already exists for this domain name"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the original mapping is unchanged and no duplicate was created.
    still_there = apigw.get_api_mapping(ApiMappingId=original_id, DomainName=domain)
    assert still_there["ApiMappingKey"] == "dup", still_there
    all_mappings = apigw.get_api_mappings(DomainName=domain)["Items"]
    assert len(all_mappings) == 1, all_mappings

    # Positive control: a mapping with a distinct key on the same domain succeeds.
    control = apigw.create_api_mapping(
        ApiId=api_id, DomainName=domain, Stage=stage_name, ApiMappingKey="distinct"
    )
    control_id = control["ApiMappingId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_api_mapping(ApiMappingId=control_id, DomainName=domain)
        )
    )

    # Independent read at the destination: both mappings are visible via get_api_mapping /
    # get_api_mappings, not just echoed back by the create call that made them.
    control_check = apigw.get_api_mapping(ApiMappingId=control_id, DomainName=domain)
    assert control_check["ApiMappingKey"] == "distinct", control_check
    final_mappings = {m["ApiMappingId"]: m["ApiMappingKey"] for m in apigw.get_api_mappings(DomainName=domain)["Items"]}
    assert final_mappings == {original_id: "dup", control_id: "distinct"}, final_mappings


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _self_signed_cert_arn(ctx, domain: str) -> str:
    """Generate a throwaway self-signed certificate via openssl and import it into ACM."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "30", "-nodes", "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
        with open(key_path, "rb") as f:
            key_bytes = f.read()
    resp = acm.import_certificate(Certificate=cert_bytes, PrivateKey=key_bytes)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_cert_when_released(acm, cert_arn)))
    return cert_arn


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


def _retry_throttled(fn, *, attempts: int = 6, base_delay: float = 3.0):
    import time

    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < attempts - 1:
                last_exc = exc
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last_exc


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


# budget.cleanup_timeout for behavioral/apigatewayv2
_CLEANUP_S = 900.0


def _delete_cert_when_released(acm, arn: str) -> None:
    """DeleteCertificate, retrying ResourceInUseException every 2 s while ACM still counts the
    domain name as a user, up to the cleanup budget; any other error raises."""
    import time

    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
