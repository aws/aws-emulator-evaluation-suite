"""update-domain-name-invalid-security-policy-bad-request."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "update-domain-name-invalid-security-policy-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying(acm, arn))
    return arn


def _create_domain_name_retrying(apigw, *, max_attempts: int = 4, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit."""
    delay = 3.0
    for attempt in range(max_attempts):
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 15.0)
                continue
            raise


def _wait_domain_available(apigw, domain_name: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = apigw.get_domain_name(domainName=domain_name)["domainNameStatus"]
    while status not in ("AVAILABLE", "FAILED"):
        if time.monotonic() >= deadline:
            raise AssertionError(f"domain name never reached AVAILABLE (status={status})")
        time.sleep(5)
        status = apigw.get_domain_name(domainName=domain_name)["domainNameStatus"]
    if status != "AVAILABLE":
        raise AssertionError(f"domain name entered status {status}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDomainName with an unsupported securityPolicy value fails BadRequestException
    and leaves the domain's current securityPolicy unchanged."""
    apigw = ctx.client("apigateway")
    domain_name = ctx.unique_name("sim2real-behav-").rstrip("-").lower() + ".example.com"
    cert_arn = _acm_import_cert(ctx, domain_name)

    created = _create_domain_name_retrying(
        apigw,
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        securityPolicy="TLS_1_2",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_domain_retrying(apigw, domain_name))
    assert created["securityPolicy"] == "TLS_1_2"
    _wait_domain_available(apigw, domain_name)

    err = _client_error(
        lambda: apigw.update_domain_name(
            domainName=domain_name,
            patchOperations=[
                {"op": "replace", "path": "/securityPolicy", "value": "NOT_A_REAL_POLICY"}
            ],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid security policy specified", (
        f"expected the exact invalid-security-policy message, got {err.get('Message')!r}"
    )

    got = apigw.get_domain_name(domainName=domain_name)
    assert got["securityPolicy"] == "TLS_1_2", "securityPolicy must remain unchanged after the rejected patch"


def _delete_domain_retrying(apigw, domain: str) -> None:
    """Delete the domain name, retrying while a prior update is still in progress or the
    call is throttled; a domain already gone is fine."""
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
    """Delete the imported certificate, retrying while the deleted domain still holds it."""
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
