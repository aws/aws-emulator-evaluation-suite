"""update-certificate-options-pending-validation-fails."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-certificate-options-pending-validation-fails"
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
    """Request a new AMAZON_ISSUED certificate under a random, non-reserved parent domain
    (real ACM fast-tracks RFC 2606 reserved names like example.com to a terminal, non-pending
    state within well under a minute, which would falsify the PENDING_VALIDATION precondition
    this check depends on). Returns (arn, domain)."""
    if domain is None:
        label = ctx.unique_name("sim2real-behav-req-").rstrip("-").lower()
        parent = f"sim2realprobe{uuid.uuid4().hex[:10]}"
        domain = f"{label}.{parent}.com"
    resp = _retry_throttle(lambda: acm.request_certificate(DomainName=domain, **kwargs))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCertificateOptions on a PENDING_VALIDATION cert fails with InvalidStateException,
    and the rejected call leaves the certificate's state and options untouched."""
    acm = ctx.client("acm")
    arn, _domain = _request_cert(ctx, acm)

    before = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert before["Status"] == "PENDING_VALIDATION", before["Status"]

    try:
        acm.update_certificate_options(CertificateArn=arn, Options={'CertificateTransparencyLoggingPreference': 'DISABLED'})
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    else:
        raise AssertionError("UpdateCertificateOptions accepted a PENDING_VALIDATION certificate")
    assert code == "InvalidStateException", f"expected InvalidStateException, got {code!r}"
    expected_message = "The selected certificate is not Issued and/or Valid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # independent read: the rejected call must not have advanced the certificate's state
    # or mutated its options.
    after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert after["Status"] == "PENDING_VALIDATION", after["Status"]
    assert after.get("Options") == before.get("Options"), (after.get("Options"), before.get("Options"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
