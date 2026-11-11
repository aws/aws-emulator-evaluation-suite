"""create-api-mapping-nonexistent-domain-not-found."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-mapping-nonexistent-domain-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping against a domain name that does not exist returns NotFoundException,
    and no mapping is left reachable through any path -- while the same call against a real
    domain succeeds."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    apigw = ctx.client("apigatewayv2")

    api_id = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-api-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_api(ApiId=api_id)))
    stage_name = "s1"
    apigw.create_stage(ApiId=api_id, StageName=stage_name, Tags=TAGS)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_stage(ApiId=api_id, StageName=stage_name)))

    missing_domain = _domain_name(ctx, "sim2real-behav-missing")
    code, message = _error_code(
        lambda: apigw.create_api_mapping(
            ApiId=api_id, DomainName=missing_domain, Stage=stage_name, ApiMappingKey="v1"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}: {message!r}"
    expected_message = "Invalid domain name identifier specified"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the domain truly never came into existence -- querying it 404s too.
    still_missing, still_missing_message = _error_code(
        lambda: apigw.get_domain_name(DomainName=missing_domain)
    )
    assert still_missing == "NotFoundException", (
        f"expected the never-created domain to still 404 on GetDomainName, got "
        f"{still_missing!r}: {still_missing_message!r}"
    )
    expected_message = "Invalid domain name identifier specified"
    assert still_missing_message == expected_message, (
        f"expected the exact message {expected_message!r}, got {still_missing_message!r}"
    )

    # Positive control: the exact same shape of call succeeds against a real domain.
    real_domain = _domain_name(ctx, "sim2real-behav-real")
    cert_arn = _self_signed_cert_arn(ctx, real_domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=real_domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
            Tags=TAGS,
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=real_domain)))
    mapping = apigw.create_api_mapping(
        ApiId=api_id, DomainName=real_domain, Stage=stage_name, ApiMappingKey="v1"
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_api_mapping(ApiMappingId=mapping["ApiMappingId"], DomainName=real_domain)
        )
    )
    items = apigw.get_api_mappings(DomainName=real_domain)["Items"]
    assert any(item["ApiMappingId"] == mapping["ApiMappingId"] for item in items), (
        f"expected mapping {mapping['ApiMappingId']!r} for the now-real domain {real_domain!r} "
        f"to be visible via GetApiMappings, got {[i['ApiMappingId'] for i in items]!r}"
    )


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _self_signed_cert_arn(ctx, domain: str) -> str:
    """Generate a throwaway self-signed certificate via openssl and import it into ACM."""
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
    resp = acm.import_certificate(
        Certificate=cert_bytes,
        PrivateKey=key_bytes,
        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_once_unused(acm, cert_arn))
    return cert_arn


def _delete_cert_once_unused(acm, cert_arn: str) -> None:
    """Delete an ACM cert, tolerating ResourceInUseException with a bounded retry: ACM's InUseBy
    list lags the API Gateway domain delete that unhooks it by a few seconds."""
    import time

    for attempt in range(6):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and attempt < 5:
                time.sleep(5.0 * (attempt + 1))
                continue
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
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
