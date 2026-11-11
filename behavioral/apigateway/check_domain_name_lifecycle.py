"""domain-name-lifecycle."""
from __future__ import annotations

import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-name-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomainName -> GetDomainName -> UpdateDomainName -> DeleteDomainName -> 404 on get."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    apigw = ctx.client("apigateway")
    domain = _apigw_test_domain(ctx, "life")
    cert_arn = _acm_import_cert(ctx, domain)

    created = _create_domain_name_retrying(
        apigw,
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        securityPolicy="TLS_1_0",
        tags={"sim2real-behav": str(uuid.uuid4())},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain))
    assert created["domainName"] == domain, (
        f"expected domainName {domain!r}, got {created['domainName']!r}"
    )
    assert created["endpointConfiguration"]["types"] == ["REGIONAL"], (
        f"expected endpointConfiguration.types == ['REGIONAL'], "
        f"got {created['endpointConfiguration']['types']!r}"
    )

    status = _poll_until(
        lambda: apigw.get_domain_name(domainName=domain)["domainNameStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    if status != "AVAILABLE":
        raise AssertionError(
            f"domain name never reached AVAILABLE (status={status})",
        )

    got = apigw.get_domain_name(domainName=domain)
    assert got["domainName"] == domain, f"expected domainName {domain!r}, got {got['domainName']!r}"
    assert got["securityPolicy"] == "TLS_1_0", (
        f"expected securityPolicy TLS_1_0 after create, got {got['securityPolicy']!r}"
    )

    apigw.update_domain_name(
        domainName=domain,
        patchOperations=[{"op": "replace", "path": "/securityPolicy", "value": "TLS_1_2"}],
    )
    # domainNameStatus does NOT reconverge to AVAILABLE on any bounded schedule after a
    # securityPolicy patch, so gating on reconvergence is not a derivable contract here --
    # the terminal read below is on the patched field itself, which the CreateDomainName-style
    # poll above already established is independently observable without needing
    # domainNameStatus back at AVAILABLE.
    updated = apigw.get_domain_name(domainName=domain)
    assert updated["securityPolicy"] == "TLS_1_2", (
        f"expected securityPolicy TLS_1_2 after update, got {updated['securityPolicy']!r}"
    )

    _delete_domain_name_retrying(apigw, domain)
    code, message = _client_error(lambda: apigw.get_domain_name(domainName=domain))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert message == "Invalid domain name identifier specified", (
        f"expected the exact NotFoundException message after delete, got {message!r}"
    )

    # the delete is not just a disappearance from reads: a mutation on the same dead id
    # must also fail, not silently recreate or resurrect state.
    update_code, update_message = _client_error(lambda: apigw.update_domain_name(
        domainName=domain,
        patchOperations=[{"op": "replace", "path": "/securityPolicy", "value": "TLS_1_0"}],
    ))
    assert update_code == "NotFoundException", (
        f"expected NotFoundException when mutating the deleted domain, got {update_code!r}"
    )
    assert update_message == "Invalid domain name identifier specified", (
        f"expected the exact NotFoundException message when mutating the deleted domain, got {update_message!r}"
    )


# ===== helpers (self-contained) =====

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
    cert_pem, key_pem = _openssl_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, arn))
    return arn


def _delete_certificate_when_released(acm, arn: str, *, timeout_s: float = 300.0, interval_s: float = 10.0):
    """ACM keeps reporting a certificate in use for a while after the domain name holding it is
    deleted; retry ResourceInUseException until a bounded deadline, then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS
    raises, because a target accepting a call real AWS refuses must not read as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_domain_name_retrying(apigw, *, max_attempts: int = 4, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit. The backoff is
    kept short (capped at a few tens of seconds total) so it doesn't eat into the
    check's overall time budget, which is also spent polling for domain provisioning."""
    from botocore.exceptions import ClientError
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


def _delete_domain_name_retrying(
    apigw, domain: str, *, timeout_s: float = 1800.0, interval_s: float = 15.0, max_attempts: int = 4
) -> None:
    """An UpdateDomainName that just completed can leave AWS reporting an "update in
    progress" BadRequestException on DeleteDomainName for a while even after
    GetDomainName already reports AVAILABLE, and can linger for many minutes. Retry
    through that, and through DeleteDomainName's separate account-wide throttling
    (TooManyRequestsException), instead of treating either as a hard failure."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    delay = interval_s
    attempt = 0
    while True:
        try:
            apigw.delete_domain_name(domainName=domain)
            return
        except ClientError as err:
            error = err.response["Error"]
            code = error["Code"]
            message = error.get("Message", "").lower()
            if (
                code == "BadRequestException"
                and "update in progres" in message
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                attempt += 1
                time.sleep(delay)
                delay = min(delay * 2, 15.0)
                continue
            raise


def _safe_delete_domain(apigw, domain: str, *, max_attempts: int = 4) -> None:
    """DeleteDomainName as a teardown safety net: a no-op if the main flow already deleted the
    domain, tolerant of the same account-wide throttling the main flow retries through."""
    delay = 3.0
    for attempt in range(max_attempts):
        try:
            apigw.delete_domain_name(domainName=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 15.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
