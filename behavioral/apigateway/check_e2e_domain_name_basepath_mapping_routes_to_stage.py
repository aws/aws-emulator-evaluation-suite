"""e2e-domain-name-basepath-mapping-routes-to-stage."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "e2e-domain-name-basepath-mapping-routes-to-stage"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base path mapping on a custom domain resolves (via Get) to the exact RestApi/stage it
    was created against, and deleting the mapping removes that routing entry entirely."""
    require_tools("openssl")

    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")

    domain_name = ctx.unique_name("sim2real-behav-").lower() + ".example.com"
    cert_pem, key_pem = _generate_self_signed_cert(domain_name)

    imported = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    cert_arn = imported["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))

    domain = apigw.create_domain_name(
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: apigw.delete_domain_name(domainName=domain_name)))
    assert domain["domainName"] == domain_name, domain

    # domainNameStatus lifecycle: PENDING/UPDATING -> AVAILABLE. Poll bounded (documented async
    # provisioning), then proceed to verify routing regardless (mapping API works pre-AVAILABLE).
    _poll_until(
        lambda: apigw.get_domain_name(domainName=domain_name)["domainNameStatus"],
        lambda status: status in ("AVAILABLE", "PENDING_CERTIFICATE_REIMPORT", "UPDATING"),
        timeout_s=120,
        interval_s=5,
    )

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: apigw.delete_rest_api(restApiId=api_id)))

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
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "live"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)

    base_path = "v1"
    apigw.create_base_path_mapping(
        domainName=domain_name,
        basePath=base_path,
        restApiId=api_id,
        stage=stage_name,
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath=base_path)
        )
    )

    mapping = apigw.get_base_path_mapping(domainName=domain_name, basePath=base_path)
    assert mapping["restApiId"] == api_id, mapping
    assert mapping["stage"] == stage_name, mapping
    assert mapping["basePath"] == base_path, mapping

    apigw.delete_base_path_mapping(domainName=domain_name, basePath=base_path)
    mapping_not_found = ("NotFoundException", "Invalid base path mapping identifier specified")
    err = _error(
        lambda: apigw.get_base_path_mapping(domainName=domain_name, basePath=base_path)
    )
    assert err == mapping_not_found, f"expected {mapping_not_found!r} on Get after delete, got {err!r}"

    # The mapping must be genuinely gone, not just absent from Get: a mutation against the same dead
    # (domainName, basePath) must also be refused.
    err = _error(
        lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath=base_path)
    )
    assert err == mapping_not_found, f"expected {mapping_not_found!r} on double-delete, got {err!r}"


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


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")


def _generate_self_signed_cert(domain_name: str) -> tuple[str, str]:
    """Generate a self-signed cert+key via the openssl CLI (no CA/DNS validation required,
    which is exactly what ACM's import_certificate is for)."""
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-nodes",
                "-subj",
                f"/CN={domain_name}",
            ],
            check=True,
            capture_output=True,
        )
        return cert_path.read_text(), key_path.read_text()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
