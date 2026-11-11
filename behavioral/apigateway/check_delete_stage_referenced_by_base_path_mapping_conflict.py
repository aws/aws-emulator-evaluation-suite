"""delete-stage-referenced-by-base-path-mapping-conflict."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-stage-referenced-by-base-path-mapping-conflict"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStage on a stage still referenced by a BasePathMapping is rejected rather than deleting it."""
    apigw = ctx.client("apigateway")

    api_id, root_id = _create_minimal_rest_api(ctx)
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: _safe_delete_stage(apigw, api_id, stage_name))

    domain_name = f"{ctx.unique_name('sim2real-bhv-dom-')}.example.com".lower()
    # REGIONAL still requires a certificate on real AWS: a REGIONAL domain name
    # needs a regionalCertificateArn. Import a throwaway self-signed cert into
    # ACM for it. Domain-name creation is also throttled account-wide on real
    # AWS (TooManyRequestsException), so retry with backoff rather than failing
    # on the first hit.
    cert_arn = _acm_import_cert(ctx, domain_name)
    _create_domain_name_retrying(
        apigw,
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain_name))
    _wait_domain_available(apigw, domain_name)

    apigw.create_base_path_mapping(domainName=domain_name, restApiId=api_id, stage=stage_name)
    ctx.on_cleanup(lambda: _safe_delete_mapping(apigw, domain_name))

    code, message = _client_error(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))
    # Real AWS rejects a stage still referenced by a BasePathMapping with BadRequestException
    # (not ConflictException, despite that being the more general-sounding fit).
    assert code == "BadRequestException", (
        f"expected BadRequestException deleting a stage still referenced by a BasePathMapping, "
        f"got {code!r}"
    )
    assert message == (
        f"Deleting stage {stage_name} failed. Please remove all base path mappings related to "
        f"the stage in your domains: {domain_name}"
    ), message

    # The stage must still be intact -- the rejected delete must not have partially applied.
    described = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert described["stageName"] == stage_name, (
        f"expected the rejected delete to leave the stage intact, got {described!r}"
    )

    # Restore: remove the dependent mapping, then the identical delete call succeeds -- the
    # rejection above was scoped to the mapping, not a general inability to delete the stage.
    apigw.delete_base_path_mapping(domainName=domain_name, basePath="(none)")
    apigw.delete_stage(restApiId=api_id, stageName=stage_name)
    gone_code, gone_message = _client_error(lambda: apigw.get_stage(restApiId=api_id, stageName=stage_name))
    assert gone_code == "NotFoundException", (
        f"expected the now-unblocked stage delete to read back not-found, got {gone_code!r}"
    )
    assert gone_message == "Invalid stage identifier specified", gone_message


def _client_error(fn: Any) -> tuple[str, str | None]:
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _openssl_self_signed_cert(common_name: str) -> tuple[str, str]:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
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
    cert_pem, key_pem = _openssl_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem.encode(), PrivateKey=key_pem.encode())
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, arn))
    return arn


def _delete_certificate_when_released(acm, arn: str, *, timeout_s: float = 300.0, interval_s: float = 10.0):
    """ACM keeps reporting a certificate in use for a while after the domain name holding it is
    deleted; retry ResourceInUseException until a bounded deadline, then raise."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_domain_name_retrying(apigw, *, max_attempts: int = 6, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit."""
    from botocore.exceptions import ClientError

    delay = 5.0
    for attempt in range(max_attempts):
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            raise


def _wait_domain_available(apigw, domain: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = apigw.get_domain_name(domainName=domain)["domainNameStatus"]
    while status not in ("AVAILABLE", "FAILED"):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"domain name never reached AVAILABLE (status={status})"
            )
        time.sleep(5)
        status = apigw.get_domain_name(domainName=domain)["domainNameStatus"]
    if status != "AVAILABLE":
        raise AssertionError(f"domain name entered status {status}")


def _safe_delete_domain(apigw, domain: str) -> None:
    try:
        apigw.delete_domain_name(domainName=domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_mapping(apigw, domain: str) -> None:
    try:
        apigw.delete_base_path_mapping(domainName=domain, basePath="(none)")
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("NotFoundException",) or
            (exc.response["Error"]["Code"] == "BadRequestException"
             and "Invalid REST API identifier" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _safe_delete_stage(apigw, api_id: str, stage_name: str) -> None:
    try:
        apigw.delete_stage(restApiId=api_id, stageName=stage_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_minimal_rest_api(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-bhv-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200", responseTemplates={}
    )
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
