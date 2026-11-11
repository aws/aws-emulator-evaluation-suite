"""delete-nonexistent-domain-name-returns-notfound."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "delete-nonexistent-domain-name-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomainName on an unknown domain fails with NotFoundException, while a real domain name
    created first deletes successfully."""
    apigw = ctx.client("apigateway")
    domain = ctx.unique_name("sim2real-nodomain-").lower() + ".example.com"

    # --- positive control: DeleteDomainName succeeds on a domain that genuinely exists ---
    cert_arn = _acm_import_cert(ctx, domain)
    _create_domain_name_retrying(
        apigw,
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain))

    status = _poll_until(
        lambda: apigw.get_domain_name(domainName=domain)["domainNameStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    if status != "AVAILABLE":
        raise AssertionError(
            f"domain name never reached AVAILABLE (status={status})"
        )

    existing = {d["domainName"] for d in _list_domain_names(apigw)}
    assert domain in existing, "the domain we just created is not visible in GetDomainNames"

    _delete_domain_name_retrying(apigw, domain)
    get_code, get_message = _client_error(lambda: apigw.get_domain_name(domainName=domain))
    assert get_code == "NotFoundException", (
        "the positive-control delete did not actually remove the domain it just created"
    )
    assert get_message == "Invalid domain name identifier specified", get_message

    # --- negative: the SAME identifier, now genuinely nonexistent, is rejected ---
    after_first_delete = {d["domainName"] for d in _list_domain_names(apigw)}
    assert domain not in after_first_delete

    code, message = _client_error(lambda: apigw.delete_domain_name(domainName=domain))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid domain name identifier specified", message

    # no side effect: the domain still does not exist (the second delete did not
    # create/mutate anything)
    after_second_delete = {d["domainName"] for d in _list_domain_names(apigw)}
    assert domain not in after_second_delete


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, arn))
    return arn


def _delete_certificate_when_released(acm, arn: str, *, timeout_s: float = 300.0, interval_s: float = 10.0):
    """ACM keeps reporting a certificate in use for a while after the domain name holding it is
    deleted; retry ResourceInUseException until a bounded deadline, then raise."""
    from botocore.exceptions import ClientError

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
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_domain_name_retrying(apigw, *, max_attempts: int = 4, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit."""
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
    """A domain name can report an "update in progress" BadRequestException on
    DeleteDomainName for a while even after GetDomainName already reports AVAILABLE, and
    DeleteDomainName is separately throttled account-wide (TooManyRequestsException). Retry
    through both instead of treating either as a hard failure."""
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


def _safe_delete_domain(apigw, domain: str) -> None:
    try:
        apigw.delete_domain_name(domainName=domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _list_domain_names(apigw):
    items = []
    kwargs = {}
    while True:
        resp = apigw.get_domain_names(**kwargs)
        items.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
        kwargs["position"] = position
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
