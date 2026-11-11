"""request-certificate-domain-validation-mismatch."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-domain-validation-mismatch"
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RequestCertificate refuses DomainValidationOptions naming a domain not on the certificate with
    InvalidDomainValidationOptionsException and the exact message and creates no certificate; the
    same call naming the certificate's own domain succeeds."""
    acm = ctx.client("acm")
    control_domain = ctx.unique_name("sim2real-behav-mismatch-ctrl-").rstrip("-") + ".example.com"
    neg_domain = ctx.unique_name("sim2real-behav-mismatch-neg-").rstrip("-") + ".example.com"
    other_domain = "unrelated-" + neg_domain

    control_resp = _retry_throttle(lambda: acm.request_certificate(
        DomainName=control_domain,
        DomainValidationOptions=[{'DomainName': control_domain, 'ValidationDomain': control_domain}],
        ValidationMethod='EMAIL',
        Tags=[{"Key": "sim2real-owner", "Value": CHECK}],
    ))
    control_arn = control_resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=control_arn), attempts=4, base_delay=3.0
        )
    )
    assert control_arn, control_resp

    try:
        result = acm.request_certificate(
            DomainName=neg_domain,
            DomainValidationOptions=[{'DomainName': other_domain, 'ValidationDomain': other_domain}],
            ValidationMethod='EMAIL',
        )
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    else:
        arn = result.get("CertificateArn")
        if arn:
            ctx.on_cleanup(lambda: _retry_throttle(lambda: acm.delete_certificate(CertificateArn=arn)))
        raise AssertionError(f"mismatched DomainValidationOptions must be rejected, got {result!r}")
    assert code == "InvalidDomainValidationOptionsException", code
    expected = (
        f"The domain specified in ValidationOptions, {other_domain}, "
        "is not the PrimaryDomain or part of SubjectAlternativeNames."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected request must not have produced a certificate.
    certs = _retry_throttle(lambda: acm.list_certificates())["CertificateSummaryList"]
    assert not any(c["DomainName"] == neg_domain for c in certs), (
        f"rejected RequestCertificate for {neg_domain} still produced a certificate: "
        f"{[c for c in certs if c['DomainName'] == neg_domain]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
