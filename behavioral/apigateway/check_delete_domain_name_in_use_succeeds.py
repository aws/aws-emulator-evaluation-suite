"""delete-domain-name-in-use-succeeds."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags

CHECK = "delete-domain-name-in-use-succeeds"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDomainName succeeds even while a BasePathMapping still references it; real AWS does
    not enforce a ConflictException/BadRequestException for this dependency -- the domain (and any
    mapping that referenced it) is deleted outright."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    apigw = ctx.client("apigateway")

    api_id, root_id = _create_minimal_rest_api(ctx)
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))

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
    ctx.on_cleanup(lambda: _safe_delete_mapping(apigw, domain_name, ""))

    # DeleteDomainName is itself subject to the same account-wide domain-name
    # API throttle (TooManyRequestsException) that CreateDomainName is; retry
    # with backoff so a transient throttle doesn't mask the observed behavior
    # under test. Real AWS does not reject this call because of the active
    # BasePathMapping: it deletes the domain (and the mapping along with it).
    _delete_domain_name_retrying(apigw, domainName=domain_name)

    # The domain must actually be gone -- the delete must have taken full effect,
    # not partially applied or silently ignored.
    domain_code, domain_message = _error(lambda: apigw.get_domain_name(domainName=domain_name))
    assert domain_code == "NotFoundException", f"expected NotFoundException, got {domain_code!r}"
    assert domain_message == "Invalid domain name identifier specified", f"unexpected message: {domain_message!r}"

    # The mapping that referenced the now-deleted domain is cascade-removed with it, not
    # left dangling: there is no domain left for it to resolve against.
    mapping_code, mapping_message = _error(lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath=""))
    assert mapping_code == "NotFoundException", f"expected NotFoundException for the mapping, got {mapping_code!r}"
    assert mapping_message == "Invalid domain name identifier specified", f"unexpected message: {mapping_message!r}"


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _delete_domain_name_retrying(apigw, max_attempts: int = 6, **kwargs) -> None:
    """DeleteDomainName is expected to succeed (real AWS does not reject it for an
    active BasePathMapping), but the call is itself subject to the same account-wide
    domain-name API throttle (TooManyRequestsException) as CreateDomainName; retry
    with backoff so a transient throttle isn't mistaken for a rejection."""
    from botocore.exceptions import ClientError

    delay = 5.0
    for attempt in range(max_attempts):
        try:
            apigw.delete_domain_name(**kwargs)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            raise


def _safe_delete_mapping(apigw, domain: str, base_path: str) -> None:
    from botocore.exceptions import ClientError

    # A mapping is cascade-deleted with its domain (that is this check's own claim), and
    # DeleteBasePathMapping on an already-gone domain answers with an unmodeled, unparsed
    # error rather than a clean NotFoundException -- so check the domain itself first.
    try:
        apigw.get_domain_name(domainName=domain)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return
        raise
    try:
        apigw.delete_base_path_mapping(domainName=domain, basePath=base_path)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


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
    cert_pem, key_pem = _openssl_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, arn))
    return arn


def _delete_cert_when_released(acm, arn: str, timeout_s: float = 180.0) -> None:
    """Delete the certificate once the deleted domain name releases it; ACM reports
    ResourceInUseException until that release completes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(10)


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
    from botocore.exceptions import ClientError

    try:
        apigw.delete_domain_name(domainName=domain)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
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
