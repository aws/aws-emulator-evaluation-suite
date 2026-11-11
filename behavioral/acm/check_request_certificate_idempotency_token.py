"""request-certificate-idempotency-token."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-idempotency-token"
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

def _unique_domain(ctx, prefix="chk"):
    """Unique DNS name under a random, non-reserved parent so the request is accepted on the
    normal path (reserved names like example.com are fast-failed by ACM risk assessment)."""
    raw = ctx.unique_name(prefix)
    label = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw.lower())
    label = label.strip("-") or "chk"
    label = label[:50]
    parent = f"sim2realprobe{uuid.uuid4().hex[:10]}"
    return f"{label}.{parent}.com"

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Same DomainName + IdempotencyToken returns the same CertificateArn; a new token creates a new cert."""
    acm = ctx.client("acm")
    domain = _unique_domain(ctx, "idem")
    # IdempotencyToken must satisfy \w+ (no hyphens), max 32 chars.
    token = uuid.uuid4().hex[:24]

    arn1 = _retry_throttle(
        lambda: acm.request_certificate(DomainName=domain, IdempotencyToken=token)
    )["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn1), attempts=4, base_delay=3.0
        )
    )

    arn2 = _retry_throttle(
        lambda: acm.request_certificate(DomainName=domain, IdempotencyToken=token)
    )["CertificateArn"]
    assert arn2 == arn1, "identical domain+token must be idempotent and return the same ARN"

    other_token = uuid.uuid4().hex[:24]
    arn3 = _retry_throttle(
        lambda: acm.request_certificate(DomainName=domain, IdempotencyToken=other_token)
    )["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn3), attempts=4, base_delay=3.0
        )
    )
    assert arn3 != arn1, "a different idempotency token must not collapse into the same certificate"

    # Terminal read is independent of RequestCertificate: DescribeCertificate must show
    # two distinct, real certificate resources for the same domain, not just two ARN
    # strings echoed back by the call that minted them.
    desc1 = _retry_throttle(lambda: acm.describe_certificate(CertificateArn=arn1))["Certificate"]
    desc3 = _retry_throttle(lambda: acm.describe_certificate(CertificateArn=arn3))["Certificate"]
    assert desc1["CertificateArn"] == arn1, desc1
    assert desc3["CertificateArn"] == arn3, desc3
    assert desc1["DomainName"] == domain, desc1
    assert desc3["DomainName"] == domain, desc3


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
