"""delete-domain-name-with-active-mapping-succeeds."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-domain-name-with-active-mapping-succeeds"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDomainName succeeds even while a base path mapping is still active;
    real AWS does not enforce a ConflictException for this dependency."""
    apigw = ctx.client("apigateway")
    api = _create_deployed_rest_api(ctx)
    domain = _apigw_test_domain(ctx, "delconflict")
    cert_arn = _acm_import_cert(ctx, domain)

    # Called for its side effect: the domain must exist for the mapping created below.
    _create_domain_name_retrying(
        apigw,
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain))
    _wait_domain_available(apigw, domain)

    apigw.create_base_path_mapping(domainName=domain, restApiId=api["id"], stage=api["stage"], basePath="")
    ctx.on_cleanup(lambda: _safe_delete_mapping(apigw, domain, ""))

    # Real AWS does not reject DeleteDomainName because of an active base path
    # mapping (unlike, say, DeleteRestApi with dependent stages): the domain is
    # deleted outright and any mapping that referenced it goes with it. Assert
    # that observed behavior rather than a ConflictException real AWS never
    # raises here.
    apigw.delete_domain_name(domainName=domain)
    domain_code, domain_message = _error(lambda: apigw.get_domain_name(domainName=domain))
    assert domain_code == "NotFoundException", f"expected NotFoundException after domain delete, got {domain_code!r}"
    assert domain_message == "Invalid domain name identifier specified", f"unexpected message: {domain_message!r}"

    # The mapping that referenced the now-deleted domain is gone with it, not left dangling.
    mapping_code, mapping_message = _error(lambda: apigw.get_base_path_mapping(domainName=domain, basePath=""))
    assert mapping_code == "NotFoundException", (
        f"expected the orphaned base path mapping lookup to 404, got {mapping_code!r}"
    )
    assert mapping_message == "Invalid domain name identifier specified", f"unexpected message: {mapping_message!r}"


# ===== helpers =====

def _apigw_test_domain(ctx, label: str) -> str:
    base = ctx.unique_name(f"sim2real-apigw-{label}-").rstrip("-").lower()
    return f"{base}.example.com"


def _openssl_self_signed_cert(common_name: str) -> tuple[str, str]:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        crt_path = Path(d) / "crt.pem"
        proc = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(crt_path),
                "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
            ],
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            raise AssertionError(f"openssl failed to generate a self-signed certificate: {proc.stderr!r}")
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


def _create_deployed_rest_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
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


def _wait_domain_available(apigw, domain: str, timeout_s=180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        status = apigw.get_domain_name(domainName=domain)["domainNameStatus"]
        if status == "AVAILABLE":
            return
        if status == "FAILED":
            raise AssertionError(f"domain name entered status {status}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"domain name never reached AVAILABLE (status={status})")
        time.sleep(5)


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


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


def _safe_delete_domain(apigw, domain: str) -> None:
    try:
        apigw.delete_domain_name(domainName=domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_mapping(apigw, domain: str, base_path: str) -> None:
    """The mapping is already cascade-removed once its owning domain is gone (asserted above),
    so a 404 here — including the unmodeled ``UnknownOperationException`` real AWS returns for an
    empty basePath against an already-deleted domain name — is cleanup of an already-gone resource,
    not a leak."""
    try:
        apigw.delete_base_path_mapping(domainName=domain, basePath=base_path)
    except ClientError as exc:
        if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 404:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
