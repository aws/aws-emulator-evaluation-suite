"""get-domain-names-lists-created."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "get-domain-names-lists-created"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDomainNames reflects a newly created domain name in its collection."""
    apigw = ctx.client("apigateway")
    domain = _apigw_test_domain(ctx, "list")
    cert_arn = _acm_import_cert(ctx, domain)

    apigw.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "get-domain-names-lists-created"},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain))

    found = _find_in_paginated(
        lambda position: apigw.get_domain_names(**({"position": position} if position else {})),
        item_key="items",
        matches=lambda item: item.get("domainName") == domain,
        timeout_s=60,
    )
    assert found is not None, f"domain {domain} not present in GetDomainNames"
    assert found["regionalCertificateArn"] == cert_arn, (
        f"regionalCertificateArn mismatch: expected {cert_arn}, got {found.get('regionalCertificateArn')}"
    )
    assert found.get("endpointConfiguration", {}).get("types") == ["REGIONAL"], (
        f"endpointConfiguration mismatch: expected ['REGIONAL'], got {found.get('endpointConfiguration')}"
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
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real-behav", "Value": "get-domain-names-lists-created"}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, arn))
    return arn


def _find_in_paginated(page_fn, *, item_key, matches, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    position = None
    while True:
        page = page_fn(position)
        for item in page.get(item_key, []):
            if matches(item):
                return item
        position = page.get("position")
        if not position or time.monotonic() >= deadline:
            return None


def _safe_delete_domain(apigw, domain: str) -> None:
    try:
        apigw.delete_domain_name(domainName=domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


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
