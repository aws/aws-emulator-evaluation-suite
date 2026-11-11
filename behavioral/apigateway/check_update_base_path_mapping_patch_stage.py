"""update-base-path-mapping-patch-stage."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags

CHECK = "update-base-path-mapping-patch-stage"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBasePathMapping repoints a mapping to a different stage without changing basePath."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    apigw = ctx.client("apigateway")

    api_id, root_id = _create_rest_api(ctx)
    _put_mock_method(ctx, api_id, root_id, "GET")
    deployment_id = apigw.create_deployment(restApiId=api_id, description="single deployment for two stages")["id"]

    stage_a = ctx.unique_name("stga").replace("-", "")[:20]
    stage_b = ctx.unique_name("stgb").replace("-", "")[:20]
    apigw.create_stage(restApiId=api_id, stageName=stage_a, deploymentId=deployment_id, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_a))
    apigw.create_stage(restApiId=api_id, stageName=stage_b, deploymentId=deployment_id, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_b))

    domain_name = ctx.unique_name("sim2real-bh").replace("_", "-") + ".example.com"
    cert_arn = _import_self_signed_certificate(ctx, domain_name)

    apigw.create_domain_name(
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain_name))

    status = _poll_until(
        lambda: apigw.get_domain_name(domainName=domain_name),
        lambda r: r["domainNameStatus"] in ("AVAILABLE", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    if status["domainNameStatus"] != "AVAILABLE":
        raise AssertionError(
            f"domain name never reached AVAILABLE: {status.get('domainNameStatusMessage')}",
        )

    created = apigw.create_base_path_mapping(domainName=domain_name, restApiId=api_id, basePath="v1", stage=stage_a)
    ctx.on_cleanup(lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath="v1"))
    assert created["basePath"] == "v1", f"expected basePath 'v1', got {created['basePath']!r}"
    assert created["stage"] == stage_a, f"expected stage {stage_a!r}, got {created['stage']!r}"

    updated = apigw.update_base_path_mapping(
        domainName=domain_name, basePath="v1",
        patchOperations=[{"op": "replace", "path": "/stage", "value": stage_b}],
    )
    assert updated["basePath"] == "v1", "UpdateBasePathMapping must not change basePath when only /stage is patched"
    assert updated["stage"] == stage_b, f"expected stage patched to {stage_b!r}, got {updated['stage']!r}"

    fetched = apigw.get_base_path_mapping(domainName=domain_name, basePath="v1")
    assert fetched["basePath"] == "v1", f"expected basePath 'v1' on independent read, got {fetched['basePath']!r}"
    assert fetched["stage"] == stage_b, (
        f"expected independent read to reflect patched stage {stage_b!r}, got {fetched['stage']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-bh-api-"), tags={"sim2real": CHECK})
    api_id = resp["id"]
    root_id = resp["rootResourceId"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id, root_id


def _put_mock_method(ctx, api_id, resource_id, http_method):
    apigw = ctx.client("apigateway")
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200")


def _import_self_signed_certificate(ctx, common_name: str) -> str:
    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "365", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        cert_pem = cert_path.read_bytes()
        key_pem = key_path.read_bytes()

    resp = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    return cert_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
