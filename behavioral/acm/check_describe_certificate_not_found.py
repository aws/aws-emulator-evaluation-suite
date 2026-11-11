"""describe-certificate-not-found."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-certificate-not-found"
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
    """Request a new AMAZON_ISSUED certificate. Returns (arn, domain)."""
    domain = domain or ctx.unique_name("sim2real-behav-req-").rstrip("-") + ".example.com"
    resp = _retry_throttle(
        lambda: acm.request_certificate(
            DomainName=domain,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
            **kwargs,
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

def _nonexistent_certificate_arn(real_arn):
    """A well-formed, same-account, same-region ARN that refers to no certificate."""
    account_id = real_arn.split(":")[4]
    return (
        f"arn:aws:acm:{real_arn.split(':')[3]}:{account_id}:certificate/"
        "00000000-0000-0000-0000-000000000000"
    )

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCertificate on a real certificate echoes its ARN and domain, while a well-formed,
    nonexistent same-account ARN yields ResourceNotFoundException with the exact message.
    """
    acm = ctx.client("acm")
    real_arn, real_domain = _request_cert(ctx, acm, ValidationMethod="DNS")

    live = acm.describe_certificate(CertificateArn=real_arn)["Certificate"]
    assert live["CertificateArn"] == real_arn, (
        f"expected DescribeCertificate on a live cert to echo its own ARN {real_arn}, "
        f"got {live.get('CertificateArn')}"
    )
    assert live["DomainName"] == real_domain, (
        f"expected DomainName {real_domain}, got {live.get('DomainName')}"
    )

    bogus_arn = _nonexistent_certificate_arn(real_arn)
    code, message = _error(lambda: acm.describe_certificate(CertificateArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent ARN, got {code}"
    )
    expected_message = f"Could not find certificate {bogus_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
