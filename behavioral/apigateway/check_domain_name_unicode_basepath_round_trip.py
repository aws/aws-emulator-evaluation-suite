"""domain-name-unicode-basepath-round-trip."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "domain-name-unicode-basepath-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base path mapping's basePath round-trips byte-for-byte through GetBasePathMapping for
    every non-alphanumeric character API Gateway permits ($-_.+!*'(),), while a basePath with
    unicode letters is refused, so a permissive store of an invalid basePath is caught."""
    apigw = ctx.client("apigateway")

    api_id, _root_id, deployment_id = _create_deployed_rest_api(ctx)
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)

    domain_name = ctx.unique_name("sim2real-behav-").replace("_", "-") + ".example.com"
    cert_pem, key_pem = _self_signed_cert(domain_name)

    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))

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

    special_base_path = "v1-api.test_release+beta!(1),'x'"
    apigw.create_base_path_mapping(
        domainName=domain_name, restApiId=api_id, basePath=special_base_path, stage=stage_name
    )
    ctx.on_cleanup(
        lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath=special_base_path)
    )

    got = apigw.get_base_path_mapping(domainName=domain_name, basePath=special_base_path)
    assert got["basePath"] == special_base_path, got["basePath"]
    assert got["restApiId"] == api_id, f"expected restApiId {api_id}, got {got['restApiId']}"
    assert got["stage"] == stage_name, f"expected stage {stage_name}, got {got['stage']}"

    # Boundary: a unicode basePath is rejected outright, not silently accepted.
    err = _error(
        lambda: apigw.create_base_path_mapping(
            domainName=domain_name, restApiId=api_id, basePath="café-日本語", stage=stage_name
        )
    )
    expected = (
        "BadRequestException",
        "A base path may contain only letters, numbers and one of $-_.+!*'(),",
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # effect-absent: the rejected unicode basePath left no mapping behind, and the
    # domain's only mapping is still the one created above -- via an independent read.
    remaining = sorted(
        m["basePath"] for m in apigw.get_base_path_mappings(domainName=domain_name)["items"]
    )
    assert remaining == [special_base_path], remaining


def _delete_certificate(acm, cert_arn: str) -> None:
    """Teardown: the certificate stays in use until the domain-name deletion settles."""
    deadline = time.monotonic() + 300
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
            time.sleep(10)


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _create_deployed_rest_api(ctx, description: str = ""):
    """Create a REST API with a mock GET method on the root resource and one deployment."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
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
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200", selectionPattern=""
    )
    deployment_id = apigw.create_deployment(restApiId=api_id, description=description)["id"]
    return api_id, root_id, deployment_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
