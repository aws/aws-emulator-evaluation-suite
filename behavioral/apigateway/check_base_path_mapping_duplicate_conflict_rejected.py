"""base-path-mapping-duplicate-conflict-rejected."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "base-path-mapping-duplicate-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second base path mapping reusing an already-mapped basePath on the same REGIONAL domain (backed by
    an imported self-signed ACM certificate) is rejected."""
    apigw = ctx.client("apigateway")

    api1_id, _r1, dep1_id = _create_deployed_rest_api(ctx)
    stage1 = "prod"
    apigw.create_stage(restApiId=api1_id, stageName=stage1, deploymentId=dep1_id)

    api2_id, _r2, dep2_id = _create_deployed_rest_api(ctx)
    stage2 = "prod"
    apigw.create_stage(restApiId=api2_id, stageName=stage2, deploymentId=dep2_id)

    domain_name = ctx.unique_name("sim2real-behav-").replace("_", "-") + ".example.com"
    cert_pem, key_pem = _self_signed_cert(domain_name)

    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, cert_arn))

    apigw.create_domain_name(
        domainName=domain_name,
        regionalCertificateName=ctx.unique_name("sim2real-behav-cert-"),
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain_name))

    status = _poll_until(
        lambda: apigw.get_domain_name(domainName=domain_name)["domainNameStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert status == "AVAILABLE", f"regional domain name failed to provision: {status}"

    base_path = "v1"
    first = apigw.create_base_path_mapping(
        domainName=domain_name, restApiId=api1_id, basePath=base_path, stage=stage1
    )
    ctx.on_cleanup(lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath=base_path))
    assert first["restApiId"] == api1_id, first

    # Break exactly one thing: try to reuse the same basePath against a different rest API.
    code, message = _error(
        lambda: apigw.create_base_path_mapping(
            domainName=domain_name, restApiId=api2_id, basePath=base_path, stage=stage2
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == "Base path already exists for this domain name", f"unexpected message {message!r}"

    # Effect absent: the original mapping still points at the first API/stage, not the second.
    unchanged = apigw.get_base_path_mapping(domainName=domain_name, basePath=base_path)
    assert unchanged["restApiId"] == api1_id, unchanged
    assert unchanged["stage"] == stage1, unchanged

    # Positive control: a distinct basePath on the same domain for the second API succeeds.
    other_base_path = "v2"
    apigw.create_base_path_mapping(
        domainName=domain_name, restApiId=api2_id, basePath=other_base_path, stage=stage2
    )
    ctx.on_cleanup(
        lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath=other_base_path)
    )
    control = apigw.get_base_path_mapping(domainName=domain_name, basePath=other_base_path)
    assert control["restApiId"] == api2_id, control
    assert control["stage"] == stage2, control


def _self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "2", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-subj", f"/CN={common_name}",
            ],
            capture_output=True,
            check=True,
        )
        return cert_path.read_bytes(), key_path.read_bytes()


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


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


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected success raises, so
    accepted input is reported as accepted rather than as a wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_rest_api_retrying(apigw, api_id: str, *, attempts: int = 6) -> None:
    """DeleteRestApi through its low account-level throttle (about one call per 30s): the two
    APIs this check creates are torn down back to back, so the second delete waits for the bucket
    to refill. Any other error propagates; the last throttle is re-raised."""
    for i in range(attempts):
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or i == attempts - 1:
                raise
        time.sleep(32)


def _create_deployed_rest_api(ctx, description: str = ""):
    """Create a REST API with a mock GET method on the root resource and one deployment."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_retrying(apigw, api_id))
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
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200", selectionPattern=""
    )
    deployment_id = apigw.create_deployment(restApiId=api_id, description=description)["id"]
    return api_id, root_id, deployment_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
