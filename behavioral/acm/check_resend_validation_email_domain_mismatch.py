"""resend-validation-email-domain-mismatch."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resend-validation-email-domain-mismatch"
GROUP = 'error-semantics'
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
    """Request a new EMAIL-validated certificate. Returns (arn, domain)."""
    # Avoid RFC 2606 reserved second-level domains such as example.com: real ACM
    # special-cases them and drives their EMAIL validation to a permanently rejected
    # InvalidStateException within well under a minute, so the positive control below
    # would never clear against one.
    domain = domain or ctx.unique_name("sim2real-behav-req-").rstrip("-") + ".com"
    resp = _retry_throttle(lambda: acm.request_certificate(DomainName=domain, ValidationMethod="EMAIL", **kwargs))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

def _resend_until_dispatched(acm, arn, domain, attempts=15, delay=6.0):
    """Bounded retry of ResendValidationEmail through ACM's transient
    InvalidStateException ("still in progress"), which gates on the certificate's
    initial-dispatch timing and is unrelated to the domain-mismatch contract this
    check exists to test."""
    last = None
    for _ in range(attempts):
        try:
            return acm.resend_validation_email(CertificateArn=arn, Domain=domain, ValidationDomain=domain)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidStateException":
                raise
            last = exc
            time.sleep(delay)
    raise last

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResendValidationEmail with a ValidationDomain that is not a superdomain of the certificate's
    domain is refused with InvalidDomainValidationOptionsException and the exact message, while
    the matching call succeeds and leaves the one EMAIL validation option in place."""
    acm = ctx.client("acm")
    arn, domain = _request_cert(ctx, acm)

    resp = _resend_until_dispatched(acm, arn, domain)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, resp["ResponseMetadata"]
    # the accepted resend leaves the certificate's one EMAIL validation option in place
    opts = acm.describe_certificate(CertificateArn=arn)["Certificate"]["DomainValidationOptions"]
    assert [(o["DomainName"], o.get("ValidationMethod")) for o in opts] == [(domain, "EMAIL")], opts

    try:
        acm.resend_validation_email(CertificateArn=arn, Domain=domain, ValidationDomain='not-' + domain)
        code = None
        message = None
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == "InvalidDomainValidationOptionsException", (
        f"expected InvalidDomainValidationOptionsException for a ValidationDomain not on "
        f"the certificate, got {code!r}"
    )
    assert message == f"The validation domain, not-{domain}, must be a superdomain of the requested domain, {domain}.", (
        f"expected the exact InvalidDomainValidationOptionsException message AWS returns, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
