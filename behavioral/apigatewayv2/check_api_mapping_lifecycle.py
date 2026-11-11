"""api-mapping-lifecycle."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-mapping-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-map"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiMapping is gettable, UpdateApiMapping changes the mapping key, DeleteApiMapping -> NotFoundException,
    and the dead mapping id then rejects both a read and a further mutation."""
    apigw = ctx.client("apigatewayv2")

    api_id = apigw.create_api(Name=ctx.unique_name("sim2real-map-api-"), ProtocolType="HTTP", Tags=TAGS)["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_api(ApiId=api_id)))

    domain = _domain_name(ctx, "sim2real-map-dn")
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

    mapping = apigw.create_api_mapping(
        ApiId=api_id, DomainName=domain, Stage=stage_name, ApiMappingKey="v1"
    )
    mapping_id = mapping["ApiMappingId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
        )
    )
    assert mapping["ApiMappingKey"] == "v1", f"expected create to echo ApiMappingKey=v1, got {mapping['ApiMappingKey']!r}"

    got = apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
    assert got["ApiMappingKey"] == "v1", f"expected GetApiMapping ApiMappingKey=v1, got {got['ApiMappingKey']!r}"
    assert got["ApiId"] == api_id, f"expected GetApiMapping ApiId={api_id!r}, got {got['ApiId']!r}"
    assert got["Stage"] == stage_name, f"expected GetApiMapping Stage={stage_name!r}, got {got['Stage']!r}"

    updated = apigw.update_api_mapping(
        ApiId=api_id, ApiMappingId=mapping_id, DomainName=domain, ApiMappingKey="v2"
    )
    assert updated["ApiMappingKey"] == "v2", f"expected update to echo ApiMappingKey=v2, got {updated['ApiMappingKey']!r}"

    got2 = apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
    assert got2["ApiMappingKey"] == "v2", f"expected GetApiMapping after update to read back ApiMappingKey=v2, got {got2['ApiMappingKey']!r}"

    apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain)

    read_code, read_message = _error_code(lambda: apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain))
    assert read_code == "NotFoundException", f"expected GetApiMapping on a deleted mapping to raise NotFoundException, got {read_code!r}"
    expected_message = f"Unable to find ApiMapping with ID {mapping_id}"
    assert read_message == expected_message, (
        f"expected the exact message {expected_message!r}, got {read_message!r}"
    )

    mutate_code, mutate_message = _error_code(
        lambda: apigw.update_api_mapping(
            ApiId=api_id, ApiMappingId=mapping_id, DomainName=domain, ApiMappingKey="v3"
        )
    )
    assert mutate_code == "NotFoundException", (
        f"expected UpdateApiMapping on a deleted mapping id to raise NotFoundException, got {mutate_code!r}"
    )
    expected_message = f"Unable to find ApiMapping with ID {mapping_id}"
    assert mutate_message == expected_message, (
        f"expected the exact message {expected_message!r}, got {mutate_message!r}"
    )


# ===== helpers =====
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
    resp = acm.import_certificate(
        Certificate=cert_bytes,
        PrivateKey=key_bytes,
        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, cert_arn))
    return cert_arn


def _delete_cert_when_released(acm, cert_arn: str) -> None:
    """The domain name's hold on the cert releases shortly after DeleteDomainName returns:
    retry ResourceInUseException every 2 s to a 40 s deadline, then raise."""
    import time

    deadline = time.monotonic() + 40
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must fail, not pass as a code mismatch.
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
