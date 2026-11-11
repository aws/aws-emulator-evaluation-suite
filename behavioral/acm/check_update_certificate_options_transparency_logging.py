"""update-certificate-options-transparency-logging."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-certificate-options-transparency-logging"
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
    """Unique DNS name under a random, non-reserved parent so the request stays on the normal
    PENDING_VALIDATION path (reserved names like example.com are fast-failed by ACM risk assessment)."""
    raw = ctx.unique_name(prefix)
    label = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw.lower())
    label = label.strip("-") or "chk"
    label = label[:50]
    parent = f"sim2realprobe{uuid.uuid4().hex[:10]}"
    return f"{label}.{parent}.com"

def _request_pending(ctx, acm, prefix="req", validation_method=None, **kwargs):
    """RequestCertificate under a random parent label so it stays PENDING_VALIDATION. Returns (arn, domain)."""
    domain = _unique_domain(ctx, prefix)
    params = {"DomainName": domain}
    if validation_method:
        params["ValidationMethod"] = validation_method
    params.update(kwargs)
    resp = _retry_throttle(lambda: acm.request_certificate(**params))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PENDING_VALIDATION certificate keeps the CT-logging preference set at request time, and
    UpdateCertificateOptions on it is refused with InvalidStateException and the exact message,
    leaving the preference unchanged."""
    acm = ctx.client("acm")
    arn, _domain = _request_pending(
        ctx, acm, prefix="cto",
        Options={"CertificateTransparencyLoggingPreference": "DISABLED"},
    )

    desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc["Status"] == "PENDING_VALIDATION", desc["Status"]
    assert desc["Options"]["CertificateTransparencyLoggingPreference"] == "DISABLED", desc["Options"]

    try:
        acm.update_certificate_options(
            CertificateArn=arn,
            Options={"CertificateTransparencyLoggingPreference": "ENABLED"},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError("UpdateCertificateOptions accepted a PENDING_VALIDATION certificate")
    assert code == "InvalidStateException", code
    expected_message = "The selected certificate is not Issued and/or Valid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = acm.describe_certificate(CertificateArn=arn)["Certificate"]["Options"]
    assert after["CertificateTransparencyLoggingPreference"] == "DISABLED", after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
