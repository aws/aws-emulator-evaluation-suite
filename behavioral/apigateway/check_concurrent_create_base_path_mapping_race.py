"""concurrent-create-base-path-mapping-race."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "concurrent-create-base-path-mapping-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateBasePathMapping calls for the same domain+basePath: exactly one
    succeeds, the other is rejected with ConflictException, and only one mapping persists."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    apigw = ctx.client("apigateway")
    acm = ctx.client("acm")

    domain_name = ctx.unique_name("sim2real-bpm-").lower() + ".example.com"
    cert_pem, key_pem = _generate_self_signed_cert(domain_name)

    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline,
        lambda: acm.delete_certificate(CertificateArn=cert_arn),
        gone=("ResourceNotFoundException",),
        retry=("ResourceInUseException", "ThrottlingException"),
    ))

    apigw.create_domain_name(
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        securityPolicy="TLS_1_2",
    )
    ctx.on_cleanup(lambda: _delete_domain_name(apigw, domain_name))

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-restapi-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_items = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(i["id"] for i in root_items if i["path"] == "/")
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    apigw.create_deployment(restApiId=api_id, stageName="prod")

    base_path = "race"
    ctx.on_cleanup(lambda: apigw.delete_base_path_mapping(domainName=domain_name, basePath=base_path))

    def _create():
        return apigw.create_base_path_mapping(
            domainName=domain_name, restApiId=api_id, basePath=base_path, stage="prod"
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        outcomes = []
        for fut in futures:
            try:
                fut.result()
                outcomes.append(("ok", None, None))
            except ClientError as exc:
                outcomes.append(("err", exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "err"]
    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)} ({outcomes})"
    assert len(failures) == 1, f"expected exactly 1 failure, got {len(failures)} ({outcomes})"
    assert failures[0][1] == "ConflictException", (
        f"expected the losing racer's error code to be ConflictException, got {failures[0][1]}"
    )
    # Which conflict the loser sees depends on how far the winner got; each is AWS's exact wording.
    conflicts = {
        "Base path already exists for this domain name",
        "Unable to complete operation due to concurrent modification. Please try again later.",
    }
    assert failures[0][2] in conflicts, failures[0][2]

    mappings = apigw.get_base_path_mappings(domainName=domain_name)["items"]
    matching = [m for m in mappings if m["basePath"] == base_path]
    assert len(matching) == 1, f"expected exactly 1 persisted base path mapping, got {len(matching)}"
    assert matching[0]["restApiId"] == api_id, (
        f"persisted mapping points at restApiId {matching[0]['restApiId']!r}, expected {api_id!r}"
    )
    assert matching[0]["stage"] == "prod", (
        f"persisted mapping points at stage {matching[0]['stage']!r}, expected 'prod'"
    )


def _generate_self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    return cert_pem, key_pem


# budget.cleanup_timeout for behavioral/apigateway, one deadline shared by every teardown of a run.
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


def _delete_domain_name(apigw, domain_name: str) -> None:
    apigw.delete_domain_name(domainName=domain_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
