"""get-base-path-mappings-lists-created."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "get-base-path-mappings-lists-created"
GROUP = "state-machine"
SERVICES = ["apigateway"]


# Prefix of the failure raised when a resource never reaches its ready state.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The failure for a resource that never reached its ready state, returned so a call site
    can raise it with ``from exc`` chaining."""
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBasePathMappings for a domain lists exactly the one mapping created: basePath v1 on the
    deployed REST API's id."""
    apigw = ctx.client("apigateway")
    api = _create_deployed_rest_api(ctx)
    domain = _apigw_test_domain(ctx, "bpmlist")
    cert_arn = _acm_import_cert(ctx, domain)

    apigw.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: apigw.delete_domain_name(domainName=domain)))
    _wait_domain_available(apigw, domain)

    apigw.create_base_path_mapping(domainName=domain, restApiId=api["id"], stage=api["stage"], basePath="v1")
    ctx.on_cleanup(lambda: _safe_delete_mapping(apigw, domain, "v1"))

    mappings = _poll_get_base_path_mappings(apigw, domain, expected_count=1)
    assert len(mappings) == 1, mappings
    matches = [m for m in mappings if m.get("basePath") == "v1"]
    assert len(matches) == 1, mappings
    assert matches[0]["restApiId"] == api["id"], (matches[0], api["id"])


# ===== helpers =====

def _apigw_test_domain(ctx, label: str) -> str:
    base = ctx.unique_name(f"sim2real-apigw-{label}-").rstrip("-").lower()
    return f"{base}.example.com"


def _openssl_self_signed_cert(common_name: str) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        crt_path = Path(d) / "crt.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(crt_path),
                "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        return crt_path.read_text(), key_path.read_text()


def _acm_import_cert(ctx, common_name: str) -> str:
    require_tools("openssl")
    cert_pem, key_pem = _openssl_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem.encode(), PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_refused(
        lambda: acm.delete_certificate(CertificateArn=arn), "ResourceInUseException"))
    return arn


def _create_deployed_rest_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"), tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.create_deployment(restApiId=api_id, stageName="prod")
    return {"id": api_id, "stage": "prod"}


def _poll_get_base_path_mappings(apigw, domain: str, expected_count: int, timeout_s: float = 60.0) -> list:
    # GetBasePathMappings on a freshly mapped domain can lag CreateBasePathMapping by a beat; poll
    # until the created record(s) are visible and populated rather than assuming immediate
    # consistency.
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        last = apigw.get_base_path_mappings(domainName=domain).get("items", [])
        if len(last) >= expected_count and all("restApiId" in m for m in last):
            return last
        time.sleep(3.0)
    raise AssertionError(f"GetBasePathMappings never returned {expected_count} populated records; last={last!r}")


def _wait_domain_available(apigw, domain: str, timeout_s=180.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = apigw.get_domain_name(domainName=domain)["domainNameStatus"]
    while status not in ("AVAILABLE", "FAILED"):
        if time.monotonic() >= deadline:
            raise _never_ready(
                f"domain name never reached AVAILABLE (status={status})"
            )
        time.sleep(2)
        status = apigw.get_domain_name(domainName=domain)["domainNameStatus"]
    if status != "AVAILABLE":
        raise AssertionError(f"domain name entered status {status}")


def _retry_refused(fn, code: str, timeout_s: float = 300.0) -> None:
    """Retry a teardown call AWS refuses with ``code`` while it is throttled or a dependency
    is still being released, every 2 s to a deadline; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != code or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete(fn) -> None:
    """Run an API Gateway delete, retrying throttling; an already deleted resource is fine."""
    try:
        _retry_refused(fn, "TooManyRequestsException")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_mapping(apigw, domain: str, base_path: str) -> None:
    try:
        apigw.delete_base_path_mapping(domainName=domain, basePath=base_path)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("NotFoundException",) or
            (exc.response["Error"]["Code"] == "BadRequestException"
             and "Invalid REST API identifier" in exc.response["Error"].get("Message", ""))
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
