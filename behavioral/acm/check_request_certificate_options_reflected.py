"""request-certificate-options-reflected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-options-reflected"
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

def _request_cert(ctx, acm, domain=None, **kwargs):
    """Request a new AMAZON_ISSUED certificate. Returns (arn, domain)."""
    domain = domain or ctx.unique_name("sim2real-behav-req-").rstrip("-") + ".example.com"
    resp = _retry_throttle(lambda: acm.request_certificate(DomainName=domain, **kwargs))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Options supplied at RequestCertificate time are persisted and echoed by
    DescribeCertificate, and the echoed value tracks what each certificate actually requested
    rather than a fixed default (CT logging preference plumbing)."""
    acm = ctx.client("acm")
    arn_disabled, _domain = _request_cert(ctx, acm,
        ValidationMethod="DNS",
        Options={"CertificateTransparencyLoggingPreference": "DISABLED"},
    )
    arn_enabled, _domain2 = _request_cert(ctx, acm,
        ValidationMethod="DNS",
        Options={"CertificateTransparencyLoggingPreference": "ENABLED"},
    )

    desc_disabled = acm.describe_certificate(CertificateArn=arn_disabled)["Certificate"]
    desc_enabled = acm.describe_certificate(CertificateArn=arn_enabled)["Certificate"]
    assert (
        desc_disabled["Options"]["CertificateTransparencyLoggingPreference"] == "DISABLED"
    ), desc_disabled.get("Options")
    assert (
        desc_enabled["Options"]["CertificateTransparencyLoggingPreference"] == "ENABLED"
    ), desc_enabled.get("Options")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
