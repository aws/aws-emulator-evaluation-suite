"""list-api-mappings-reflects-created."""
from __future__ import annotations

import subprocess
import tempfile
import time
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "list-api-mappings-reflects-created"
GROUP = "data-plane"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApiMappings immediately reflects a newly created ApiMapping for a
    domain, and stops listing it after DeleteApiMapping."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    apigw = ctx.client("apigatewayv2")
    acm = ctx.client("acm")

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-http-"),
        ProtocolType="HTTP",
        Tags={"sim2real-check": CHECK},
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    stage_name = "prod"
    apigw.create_stage(ApiId=api_id, StageName=stage_name)

    domain_name = f"{ctx.unique_name('sim2real-dom-').lower()}.example.com".replace("_", "-")

    cert_pem, key_pem = _self_signed_cert(domain_name)
    cert_resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    cert_arn = cert_resp["CertificateArn"]
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline,
        lambda: acm.delete_certificate(CertificateArn=cert_arn),
        gone=("ResourceNotFoundException",),
        retry=("ResourceInUseException", "ThrottlingException"),
    ))

    apigw.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[
            {"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}
        ],
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain_name))

    mapping = apigw.create_api_mapping(
        ApiId=api_id, DomainName=domain_name, Stage=stage_name
    )
    mapping_id = mapping["ApiMappingId"]
    ctx.on_cleanup(lambda: _safe_delete_mapping(apigw, domain_name, mapping_id))

    items = _poll_until(
        lambda: apigw.get_api_mappings(DomainName=domain_name)["Items"],
        lambda its: any(i["ApiMappingId"] == mapping_id for i in its),
        timeout_s=20,
    )
    assert any(i["ApiMappingId"] == mapping_id for i in items), (
        f"GetApiMappings never listed {mapping_id!r} for {domain_name!r}, saw {items!r}"
    )

    apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name)

    items_after = _poll_until(
        lambda: apigw.get_api_mappings(DomainName=domain_name)["Items"],
        lambda its: not any(i["ApiMappingId"] == mapping_id for i in its),
        timeout_s=20,
    )
    assert not any(i["ApiMappingId"] == mapping_id for i in items_after), (
        "GetApiMappings still lists the mapping after DeleteApiMapping"
    )

    mapping_gone = f"Unable to find ApiMapping with ID {mapping_id}"
    try:
        apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name)
        raise AssertionError("GetApiMapping succeeded for an ApiMappingId already deleted")
    except apigw.exceptions.NotFoundException as exc:
        assert exc.response["Error"]["Message"] == mapping_gone, exc.response["Error"]

    try:
        apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name)
        raise AssertionError("DeleteApiMapping succeeded twice for the same ApiMappingId")
    except apigw.exceptions.NotFoundException as exc:
        assert exc.response["Error"]["Message"] == mapping_gone, exc.response["Error"]


def _self_signed_cert(domain_name):
    """Generate a throw-away self-signed cert+key pair (PEM bytes) for the
    given domain name, using the openssl CLI (no external service calls)."""
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "2", "-nodes",
                "-subj", f"/CN={domain_name}",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
        return cert_pem, key_pem


def _poll_until(probe, predicate, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


# budget.cleanup_timeout for behavioral/apigatewayv2, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _teardown(teardown_deadline, fn, gone=(), retry=()) -> None:
    """Teardown: done when fn succeeds or answers a `gone` code; retry the `retry` codes every
    2 s to the shared cleanup deadline, and raise everything else."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_mapping(apigw, domain_name, mapping_id):
    try:
        apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain_name)
    except apigw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

