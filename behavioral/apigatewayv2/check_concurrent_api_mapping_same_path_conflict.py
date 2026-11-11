"""concurrent-api-mapping-same-path-conflict."""
from __future__ import annotations

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "concurrent-api-mapping-same-path-conflict"
GROUP = "concurrency"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateApiMapping calls for the same domain+key race to exactly one winner."""
    apigwv2 = ctx.client("apigatewayv2")
    domain_name = _create_domain_name(ctx)
    api_id = _create_http_api(ctx)
    _create_stage(ctx, api_id, "dev")
    _create_stage(ctx, api_id, "prod")

    mapping_key = "orders"

    def _attempt(stage):
        return apigwv2.create_api_mapping(
            DomainName=domain_name, ApiId=api_id, Stage=stage, ApiMappingKey=mapping_key
        )

    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_attempt, s) for s in ("dev", "prod")]
        for f in futures:
            try:
                results.append(("ok", f.result()))
            except ClientError as e:
                results.append(("error", (e.response["Error"]["Code"], e.response["Error"]["Message"])))

    successes = [r for kind, r in results if kind == "ok"]
    failure_codes = [r for kind, r in results if kind == "error"]
    assert len(successes) == 1, f"expected exactly one winning CreateApiMapping, got {len(successes)}"
    assert len(failure_codes) == 1, f"expected exactly one losing CreateApiMapping, got {len(failure_codes)}"
    assert failure_codes[0] == ("ConflictException", "ApiMapping key already exists for this domain name"), (
        f"expected the losing CreateApiMapping to fail with ConflictException, got {failure_codes[0]!r}"
    )

    winner_mapping_id = successes[0]["ApiMappingId"]
    ctx.on_cleanup(
        lambda: apigwv2.delete_api_mapping(DomainName=domain_name, ApiMappingId=winner_mapping_id)
    )

    listing = apigwv2.get_api_mappings(DomainName=domain_name)["Items"]
    matching = [m for m in listing if m["ApiMappingKey"] == mapping_key]
    assert len(matching) == 1, f"expected exactly one persisted mapping for the key, got {len(matching)}"
    assert matching[0]["ApiMappingId"] == winner_mapping_id, (
        f"expected the persisted mapping to be the winner {winner_mapping_id!r}, "
        f"got {matching[0]['ApiMappingId']!r}"
    )


def _import_self_signed_cert(ctx, common_name):
    acm = ctx.client("acm")
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem, Tags=TAGS_KV)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying_in_use(acm, cert_arn))
    return cert_arn


def _delete_cert_retrying_in_use(acm, cert_arn, deadline_s=45.0):
    """ACM's InUseBy bookkeeping for a cert backing a custom domain name lags the domain's own
    deletion, so an immediate DeleteCertificate can see ResourceInUseException even though the
    domain that referenced it is already gone. Retry within the cleanup budget instead of leaking."""
    import time

    deadline = time.monotonic() + deadline_s
    delay = 3.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 10.0)


def _create_domain_name(ctx):
    apigwv2 = ctx.client("apigatewayv2")
    label = ctx.unique_name("sim2real-apigwv2-").lower().replace("_", "-")
    domain_name = f"{label}.example.com"
    cert_arn = _import_self_signed_cert(ctx, domain_name)
    apigwv2.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[
            {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
        ],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: apigwv2.delete_domain_name(DomainName=domain_name))
    return domain_name


def _create_http_api(ctx):
    apigwv2 = ctx.client("apigatewayv2")
    resp = apigwv2.create_api(Name=ctx.unique_name("sim2real-api-"), ProtocolType="HTTP", Tags=TAGS)
    api_id = resp["ApiId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api(ApiId=api_id))
    return api_id


def _create_stage(ctx, api_id, stage_name):
    apigwv2 = ctx.client("apigatewayv2")
    apigwv2.create_stage(ApiId=api_id, StageName=stage_name, Tags=TAGS)
    ctx.on_cleanup(lambda: apigwv2.delete_stage(ApiId=api_id, StageName=stage_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
