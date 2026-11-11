"""request-certificate-domain-validation-options."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-domain-validation-options"
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
    domain = domain or ctx.unique_name("sim2real-behav-req-").rstrip("-") + ".example.com"
    resp = _retry_throttle(lambda: acm.request_certificate(
        DomainName=domain, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    ))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCertificate's DomainValidationOptions describe the requested domain's DNS challenge
    (a CNAME under the domain while pending, or FAILED), and a certificate for the unvalidated
    domain is never ISSUED."""
    acm = ctx.client("acm")
    arn, domain = _request_cert(ctx, acm, ValidationMethod="DNS")

    def _dvos():
        desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        return desc.get("DomainValidationOptions", [])

    dvos = _poll_until(
        _dvos,
        lambda d: any(e.get("DomainName") == domain for e in d),
        timeout_s=120,
        interval_s=5,
    )
    matching = [d for d in dvos if d["DomainName"] == domain]
    assert matching, f"no DomainValidationOptions entry for {domain}: {dvos}"
    entry = matching[0]

    assert entry["ValidationDomain"] == domain, entry
    assert entry["ValidationMethod"] == "DNS", entry
    # SUCCESS is excluded: this domain is never DNS-delegated to us, so ACM can
    # never observe the CNAME proof and complete validation for it.
    assert entry["ValidationStatus"] in {
        "PENDING_VALIDATION",
        "FAILED",
    }, entry

    # While the challenge is outstanding, ACM must publish a CNAME record to prove
    # domain control; the record is scoped under the requested domain.
    if entry["ValidationStatus"] == "PENDING_VALIDATION" and "ResourceRecord" in entry:
        rr = entry["ResourceRecord"]
        assert rr["Type"] == "CNAME", rr
        assert domain in rr["Name"], rr

    # State-machine core: no unvalidated domain is ever issued a certificate.
    status = acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"]
    assert status != "ISSUED", f"unvalidated domain was issued a certificate: {status}"
    assert status in {"PENDING_VALIDATION", "FAILED", "VALIDATION_TIMED_OUT"}, status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
