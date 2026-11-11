"""update-domain-name-invalid-security-policy-rejected."""
from __future__ import annotations

import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "update-domain-name-invalid-security-policy-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDomainName rejects securityPolicy TLS_9_9 with BadRequestException; the policy is kept.
    A valid securityPolicy patch on the same domain succeeds first, so only the value is refused.
    """
    apigw = ctx.client("apigateway")
    domain = _apigw_test_domain(ctx, "secpol")
    cert_arn = _acm_import_cert(ctx, domain)

    apigw.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        securityPolicy="TLS_1_2",
        tags={"sim2real-behav": str(uuid.uuid4())},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain))
    _wait_domain_available(apigw, domain)

    # Positive control: a valid patch on the SAME operation must succeed, so a later rejection
    # is attributable to the bad value and not to UpdateDomainName being broken for this domain.
    apigw.update_domain_name(
        domainName=domain,
        patchOperations=[{"op": "replace", "path": "/securityPolicy", "value": "TLS_1_0"}],
    )
    _wait_domain_available(apigw, domain)
    after_valid = apigw.get_domain_name(domainName=domain)
    assert after_valid["securityPolicy"] == "TLS_1_0", (
        f"expected securityPolicy TLS_1_0 after a valid patch, got {after_valid['securityPolicy']!r}"
    )

    error = _client_error(lambda: apigw.update_domain_name(
        domainName=domain,
        patchOperations=[{"op": "replace", "path": "/securityPolicy", "value": "TLS_9_9"}],
    ))
    assert error["Code"] == "BadRequestException", f"expected BadRequestException, got {error['Code']!r}"
    assert error["Message"] == "Invalid security policy specified", (
        f"expected the exact invalid-security-policy message, got {error['Message']!r}"
    )

    unchanged = apigw.get_domain_name(domainName=domain)
    assert unchanged["securityPolicy"] == "TLS_1_0", (
        f"expected securityPolicy unchanged at TLS_1_0 after the rejected patch, got {unchanged['securityPolicy']!r}"
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
        Tags=[{"Key": "sim2real-behav", "Value": str(uuid.uuid4())}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying(acm, arn))
    return arn


def _wait_domain_available(apigw, domain: str, timeout_s=600.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = apigw.get_domain_name(domainName=domain)["domainNameStatus"]
    while status not in ("AVAILABLE", "FAILED"):
        if time.monotonic() >= deadline:
            raise AssertionError(f"domain name never reached AVAILABLE (status={status})")
        time.sleep(5)
        status = apigw.get_domain_name(domainName=domain)["domainNameStatus"]
    if status != "AVAILABLE":
        raise AssertionError(f"domain name entered status {status}")


def _client_error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe_delete_domain(apigw, domain: str) -> None:
    """Delete the domain, retrying while a prior update is still propagating; already-gone is fine."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 120.0
    while True:
        try:
            apigw.delete_domain_name(domainName=domain)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code in ("BadRequestException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _delete_cert_retrying(acm, arn: str) -> None:
    """Delete the imported certificate, retrying while the just-deleted domain still holds it."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 180.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
