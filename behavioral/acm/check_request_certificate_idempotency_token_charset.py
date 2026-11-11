"""request-certificate-idempotency-token-charset."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-idempotency-token-charset"
GROUP = 'overly-permissive'
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


def _unique_domain(ctx, prefix="chk"):
    """Unique DNS name under a random, non-reserved parent label."""
    raw = ctx.unique_name(prefix)
    label = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw.lower())
    label = label.strip("-") or "chk"
    label = label[:50]
    parent = f"sim2realprobe{uuid.uuid4().hex[:10]}"
    return f"{label}.{parent}.com"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RequestCertificate rejects an IdempotencyToken violating \\w+ and creates no certificate,
    while a well-formed token is accepted, attributing the rejection to the charset."""
    acm = ctx.client("acm")

    # Positive control: a well-formed (\w+) token is accepted and creates a real certificate.
    good_domain = _unique_domain(ctx, "idemok")
    good_token = uuid.uuid4().hex[:24]
    good_arn = _retry_throttle(
        lambda: acm.request_certificate(DomainName=good_domain, IdempotencyToken=good_token)
    )["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=good_arn), attempts=4, base_delay=3.0
        )
    )
    assert good_arn, "a well-formed IdempotencyToken must be accepted"

    # Negative: a token with hyphens violates the modeled \w+ pattern and must be refused
    # before any certificate is created.
    bad_domain = _unique_domain(ctx, "idembad")
    try:
        acm.request_certificate(
            DomainName=bad_domain,
            IdempotencyToken="bad-token-with-hyphens",
        )
        raise AssertionError(
            "RequestCertificate with a hyphenated IdempotencyToken must be rejected"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "ValidationException", code
    expected = (
        "1 validation error detected: Value of the input at 'idempotencyToken' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: \w+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: an independent read shows no certificate was created for the refused request.
    resp = acm.list_certificates(CertificateStatuses=["PENDING_VALIDATION"], MaxItems=1000)
    domains = {s["DomainName"] for s in resp.get("CertificateSummaryList", [])}
    assert bad_domain not in domains, (
        "a certificate must not have been created for the rejected request"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
