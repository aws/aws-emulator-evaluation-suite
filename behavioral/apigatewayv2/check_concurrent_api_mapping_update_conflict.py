"""concurrent-api-mapping-update-conflict."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "concurrent-api-mapping-update-conflict"
GROUP = "concurrency"
SERVICES = ["apigatewayv2"]
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-mapconc"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two ApiMappings on one domain racing UpdateApiMapping to the same mapping key yield exactly
    one success and one ConflictException, never two mappings claiming the same key."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    apigw = ctx.client("apigatewayv2")

    domain = _domain_name(ctx, "sim2real-behav-mapconc")
    cert_arn = _self_signed_cert_arn(ctx, domain, teardown_deadline)
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

    api1 = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-mapapi1-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_api(ApiId=api1)))
    apigw.create_stage(ApiId=api1, StageName="s1", Tags=TAGS)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_stage(ApiId=api1, StageName="s1")))

    api2 = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-mapapi2-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_api(ApiId=api2)))
    apigw.create_stage(ApiId=api2, StageName="s2", Tags=TAGS)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_stage(ApiId=api2, StageName="s2")))

    mapping1 = apigw.create_api_mapping(ApiId=api1, DomainName=domain, Stage="s1", ApiMappingKey="race-a")
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_api_mapping(ApiMappingId=mapping1["ApiMappingId"], DomainName=domain)
        )
    )
    mapping2 = apigw.create_api_mapping(ApiId=api2, DomainName=domain, Stage="s2", ApiMappingKey="race-b")
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_api_mapping(ApiMappingId=mapping2["ApiMappingId"], DomainName=domain)
        )
    )

    shared_key = "race-shared"

    def _claim(mapping_id, api_id):
        return apigw.update_api_mapping(
            ApiId=api_id, ApiMappingId=mapping_id, DomainName=domain, ApiMappingKey=shared_key
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut1 = pool.submit(_claim, mapping1["ApiMappingId"], api1)
        fut2 = pool.submit(_claim, mapping2["ApiMappingId"], api2)
        outcome1 = _outcome(fut1)
        outcome2 = _outcome(fut2)

    successes = [o for o in (outcome1, outcome2) if o[0] == "ok"]
    failures = [o for o in (outcome1, outcome2) if o[0] == "error"]
    assert len(successes) == 1, f"expected exactly one winner, got {(outcome1, outcome2)!r}"
    assert len(failures) == 1, f"expected exactly one loser, got {(outcome1, outcome2)!r}"
    assert failures[0][1:] == ("ConflictException", "ApiMapping key already exists for this domain name"), (
        f"expected ConflictException, got {failures[0][1:]!r}"
    )

    final1 = apigw.get_api_mapping(ApiMappingId=mapping1["ApiMappingId"], DomainName=domain)
    final2 = apigw.get_api_mapping(ApiMappingId=mapping2["ApiMappingId"], DomainName=domain)
    if outcome1[0] == "ok":
        assert final1["ApiMappingKey"] == shared_key, (
            f"winner's key should be {shared_key!r}, got {final1['ApiMappingKey']!r}"
        )
        assert final2["ApiMappingKey"] == "race-b", (
            f"loser's write must not apply, expected 'race-b', got {final2['ApiMappingKey']!r}"
        )
    else:
        assert final2["ApiMappingKey"] == shared_key, (
            f"winner's key should be {shared_key!r}, got {final2['ApiMappingKey']!r}"
        )
        assert final1["ApiMappingKey"] == "race-a", (
            f"loser's write must not apply, expected 'race-a', got {final1['ApiMappingKey']!r}"
        )


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _self_signed_cert_arn(ctx, domain: str, teardown_deadline) -> str:
    """Generate a throwaway self-signed certificate via openssl and import it into ACM."""
    acm = ctx.client("acm")
    require_tools("openssl")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline,
        lambda: acm.delete_certificate(CertificateArn=cert_arn),
        gone=("ResourceNotFoundException",),
        retry=("ResourceInUseException", "ThrottlingException"),
    ))
    return cert_arn


def _outcome(future):
    try:
        future.result()
        return ("ok", None, None)
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"], exc.response["Error"]["Message"])


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


# budget.cleanup_timeout for behavioral/apigatewayv2, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _teardown(teardown_deadline, fn, gone=(), retry=()) -> None:
    """Teardown: done when fn succeeds or answers a `gone` code; retry the `retry` codes every
    2 s to the shared cleanup deadline, and raise everything else."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
