"""custom-domain-basepath-remap-flow."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "custom-domain-basepath-remap-flow"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBasePathMapping moves a base path from API A/stage a to API B/stage b;
    GetBasePathMapping reflects the remap and each API's GetExport carries its own title."""
    domain_name = ctx.unique_name("sim2real-domain-").lower() + ".example.com"
    cert_pem, key_pem = _self_signed_cert(domain_name)

    acm = ctx.client("acm")
    # ACM import does no domain validation, so a REGIONAL domain needs no real domain or CloudFront.
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, cert_arn))

    apigw = ctx.client("apigateway")
    apigw.create_domain_name(
        domainName=domain_name,
        regionalCertificateName=ctx.unique_name("sim2real-domain-cert-"),
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

    api_a = _create_mock_api(ctx, apigw, "sim2real-domain-api-a-", "a")
    api_b = _create_mock_api(ctx, apigw, "sim2real-domain-api-b-", "b")

    apigw.create_base_path_mapping(
        domainName=domain_name, restApiId=api_a["id"], stage="a", basePath="v1"
    )
    ctx.on_cleanup(lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath="v1"))

    mapping = apigw.get_base_path_mapping(domainName=domain_name, basePath="v1")
    assert mapping["restApiId"] == api_a["id"], (
        f"initial mapping must target API A: expected {api_a['id']!r}, got {mapping['restApiId']!r}"
    )
    assert mapping["stage"] == "a", f"initial mapping must target stage 'a', got {mapping['stage']!r}"

    title_a = _export_title(apigw, api_a["id"], "a")
    assert title_a == api_a["name"], (
        f"export served for base path 'v1' must reflect API A's title: "
        f"expected {api_a['name']!r}, got {title_a!r}"
    )

    apigw.update_base_path_mapping(
        domainName=domain_name,
        basePath="v1",
        patchOperations=[
            {"op": "replace", "path": "/restapiId", "value": api_b["id"]},
            {"op": "replace", "path": "/stage", "value": "b"},
        ],
    )
    remapped = apigw.get_base_path_mapping(domainName=domain_name, basePath="v1")
    assert remapped["restApiId"] == api_b["id"], "remap must move the mapping onto API B"
    assert remapped["stage"] == "b", f"remap must move the mapping onto stage 'b', got {remapped['stage']!r}"

    title_b = _export_title(apigw, api_b["id"], "b")
    assert title_b == api_b["name"], (
        f"export served for base path 'v1' must now reflect API B's title: "
        f"expected {api_b['name']!r}, got {title_b!r}"
    )
    assert title_b != title_a, (
        f"export served for base path 'v1' must change after remap: "
        f"still got API A's title {title_b!r}"
    )


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


def _create_mock_api(ctx, apigw, prefix: str, stage_name: str) -> dict:
    name = ctx.unique_name(prefix)
    rest_api_id = apigw.create_rest_api(name=name)["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(
        restApiId=rest_api_id, parentId=root_id, pathPart="ping"
    )["id"]
    apigw.put_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
    )
    apigw.create_deployment(restApiId=rest_api_id, stageName=stage_name)
    return {"id": rest_api_id, "name": name}


def _export_title(apigw, rest_api_id: str, stage_name: str) -> str:
    export = apigw.get_export(restApiId=rest_api_id, stageName=stage_name, exportType="oas30")
    doc = json.loads(export["body"].read())
    return doc["info"]["title"]


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


# budget.cleanup_timeout for behavioral/apigateway
_CLEANUP_S = 900.0


def _delete_cert_when_released(acm, arn: str) -> None:
    """DeleteCertificate, retrying ResourceInUseException every 2 s while ACM still counts the
    deleted domain name as a user, up to the cleanup budget; any other error raises."""
    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
