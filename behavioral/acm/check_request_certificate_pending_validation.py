"""request-certificate-pending-validation."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-pending-validation"
GROUP = 'lifecycle'
SERVICES = ['acm']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)

def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")

def _request_cert(ctx, acm, domain=None, **kwargs):
    """Request a new AMAZON_ISSUED certificate. Returns (arn, domain)."""
    # A random, non-reserved parent keeps the request on the PENDING_VALIDATION path: ACM
    # fast-fails reserved names such as example.com, which suppresses the DNS validation
    # ResourceRecord asserted below.
    domain = domain or (
        ctx.unique_name("sim2real-behav-req-").rstrip("-").lower()
        + f".sim2realprobe{uuid.uuid4().hex[:10]}.com"
    )
    resp = _retry_throttle(
        lambda: acm.request_certificate(
            DomainName=domain,
            Tags=[{"Key": "Name", "Value": domain}, {"Key": "sim2real", "Value": CHECK}],
            **kwargs,
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_if_present(acm, arn))
    return arn, domain


def _delete_if_present(acm, arn):
    """Teardown: delete the certificate unless the check already did."""
    try:
        _retry_throttle(lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error(fn):
    """Run fn, which must be refused; return the (code, HTTP status, message) of the refusal."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected an error but the call succeeded: {result!r}")


def _listed_arns(acm):
    """Every not-yet-issued certificate ARN, paginated."""
    arns = []
    statuses = ["PENDING_VALIDATION", "FAILED", "VALIDATION_TIMED_OUT"]
    for page in acm.get_paginator("list_certificates").paginate(CertificateStatuses=statuses):
        arns.extend(c["CertificateArn"] for c in page.get("CertificateSummaryList", []))
    return arns

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestCertificate creates a regional AMAZON_ISSUED RSA-2048 certificate for the domain that
    enters validation instead of being ISSUED, and publishes a CNAME validation record while it is
    PENDING_VALIDATION."""
    acm = ctx.client("acm")
    arn, domain = _request_cert(ctx, acm, ValidationMethod="DNS")
    arn_prefix = f"arn:aws:acm:{ctx.region}:{ctx.account}:certificate/"
    assert arn.startswith(arn_prefix), f"expected the certificate ARN to start with {arn_prefix!r}, got {arn!r}"

    def _desc():
        return acm.describe_certificate(CertificateArn=arn)["Certificate"]

    desc = _poll_until(
        _desc,
        lambda d: "DomainName" in d and "Status" in d and "Type" in d,
        timeout_s=120,
        interval_s=5,
    )
    assert desc["CertificateArn"] == arn, desc
    assert desc["DomainName"] == domain, desc
    assert desc["Type"] == "AMAZON_ISSUED", desc["Type"]
    assert desc["SubjectAlternativeNames"] == [domain], desc.get(
        "SubjectAlternativeNames"
    )
    # RequestCertificate's default key algorithm is RSA 2048, which AWS returns as 'RSA-2048'.
    assert desc["KeyAlgorithm"] == "RSA-2048", desc.get("KeyAlgorithm")
    # A requested certificate enters validation and is never born ISSUED; for an unresolvable
    # domain ACM races PENDING_VALIDATION to FAILED, so both are valid outcomes.
    assert desc["Status"] != "ISSUED", "requested cert was issued without validation"
    assert desc["Status"] in {
        "PENDING_VALIDATION",
        "FAILED",
        "VALIDATION_TIMED_OUT",
    }, desc["Status"]

    # DNS validation publishes the CNAME the owner must create; it appears asynchronously, and
    # only while the certificate is PENDING_VALIDATION (a FAILED request publishes no record).
    def _record_or_terminal(d):
        if d.get("Status") != "PENDING_VALIDATION":
            return True
        return bool(d.get("DomainValidationOptions")) and "ResourceRecord" in d["DomainValidationOptions"][0]

    with_record = _poll_until(
        _desc,
        _record_or_terminal,
        timeout_s=120,
        interval_s=5,
        description="DomainValidationOptions[0].ResourceRecord published or the request left PENDING_VALIDATION",
    )
    if with_record.get("Status") == "PENDING_VALIDATION":
        record = with_record["DomainValidationOptions"][0]["ResourceRecord"]
        assert record.get("Type") == "CNAME", f"expected a CNAME validation record, got {record!r}"
        assert record.get("Name") and record.get("Value"), f"expected a named CNAME with a value, got {record!r}"

    # ListCertificates is eventually consistent with RequestCertificate and DeleteCertificate.
    _poll_until(
        lambda: _listed_arns(acm), lambda arns: arn in arns, timeout_s=120, interval_s=5,
        description=f"ListCertificates listing {arn!r} before delete",
    )
    acm.delete_certificate(CertificateArn=arn)

    code, status, message = _error(lambda: acm.describe_certificate(CertificateArn=arn))
    assert code == "ResourceNotFoundException", f"DescribeCertificate after delete: got {code!r}"
    assert status == 400, f"DescribeCertificate after delete: expected HTTP 400, got {status!r}"
    expected_message = f"Could not find certificate {arn}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    _poll_until(
        lambda: _listed_arns(acm), lambda arns: arn not in arns, timeout_s=120, interval_s=5,
        description=f"ListCertificates no longer listing the deleted certificate {arn!r}",
    )
    code, status, message = _error(
        lambda: acm.add_tags_to_certificate(
            CertificateArn=arn, Tags=[{"Key": "sim2real-post-delete-probe", "Value": "x"}]
        )
    )
    assert code == "ResourceNotFoundException", f"AddTagsToCertificate after delete: got {code!r}"
    assert status == 400, f"AddTagsToCertificate after delete: expected HTTP 400, got {status!r}"
    expected_message = f"Could not find certificate {arn}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
