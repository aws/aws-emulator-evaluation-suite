"""base-path-mapping-lifecycle."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "base-path-mapping-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBasePathMapping -> Get -> Update -> Delete fully removes the mapping."""
    apigw = ctx.client("apigateway")
    api = _create_deployed_rest_api(ctx)
    domain = _apigw_test_domain(ctx, "bpm")
    cert_arn = _acm_import_cert(ctx, domain)

    apigw.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain))
    _wait_domain_available(apigw, domain)

    created = apigw.create_base_path_mapping(
        domainName=domain, restApiId=api["id"], stage=api["stage"], basePath="v1",
    )
    ctx.on_cleanup(lambda: _safe_delete_mapping(apigw, domain, "v1"))
    ctx.on_cleanup(lambda: _safe_delete_mapping(apigw, domain, "v2"))
    assert created["basePath"] == "v1", f"expected basePath 'v1', got {created['basePath']!r}"
    assert created["restApiId"] == api["id"], f"expected restApiId {api['id']!r}, got {created['restApiId']!r}"

    got = apigw.get_base_path_mapping(domainName=domain, basePath="v1")
    assert got["restApiId"] == api["id"], f"expected restApiId {api['id']!r}, got {got['restApiId']!r}"
    assert got["stage"] == api["stage"], f"expected stage {api['stage']!r}, got {got['stage']!r}"

    updated = apigw.update_base_path_mapping(
        domainName=domain, basePath="v1",
        patchOperations=[{"op": "replace", "path": "/basePath", "value": "v2"}],
    )
    assert updated["basePath"] == "v2", f"expected renamed basePath 'v2', got {updated['basePath']!r}"
    code, message = _error(lambda: apigw.get_base_path_mapping(domainName=domain, basePath="v1"))
    assert code == "NotFoundException", f"renaming basePath v1 -> v2 must retire the old basePath 'v1', got {code!r}"
    assert message == "Invalid base path mapping identifier specified", f"unexpected message {message!r}"
    got_v2 = apigw.get_base_path_mapping(domainName=domain, basePath="v2")
    assert got_v2["restApiId"] == api["id"], (
        f"expected restApiId {api['id']!r} under renamed basePath 'v2', got {got_v2['restApiId']!r}"
    )

    apigw.delete_base_path_mapping(domainName=domain, basePath="v2")
    code, message = _error(lambda: apigw.get_base_path_mapping(domainName=domain, basePath="v2"))
    assert code == "NotFoundException", f"GetBasePathMapping must NotFoundException after DeleteBasePathMapping, got {code!r}"
    assert message == "Invalid base path mapping identifier specified", f"unexpected message {message!r}"
    code, message = _error(
        lambda: apigw.update_base_path_mapping(
            domainName=domain, basePath="v2",
            patchOperations=[{"op": "replace", "path": "/basePath", "value": "v3"}],
        )
    )
    assert code == "NotFoundException", f"UpdateBasePathMapping on a deleted basePath must also NotFoundException, got {code!r}"
    assert message == "Invalid base path mapping identifier specified", f"unexpected message {message!r}"

    recreated = apigw.create_base_path_mapping(
        domainName=domain, restApiId=api["id"], stage=api["stage"], basePath="v2",
    )
    assert recreated["basePath"] == "v2", "a deleted basePath must be immediately reusable"
    got_recreated = apigw.get_base_path_mapping(domainName=domain, basePath="v2")
    assert got_recreated["restApiId"] == api["id"], (
        f"expected restApiId {api['id']!r} on the recreated mapping, got {got_recreated['restApiId']!r}"
    )


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
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, arn))
    return arn


def _delete_cert_when_released(acm, arn: str, *, timeout_s: float = 240.0) -> None:
    """DeleteCertificate, waiting out ResourceInUseException while ACM still sees the just-deleted
    domain name as a user of the certificate; any other error, or a cert still in use at the
    deadline, propagates so a leaked certificate fails the cleanup instead of passing silently."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _create_deployed_rest_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-api-"), tags={"sim2real": CHECK})["id"]
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_delete_domain(apigw, domain: str) -> None:
    try:
        apigw.delete_domain_name(domainName=domain)
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
