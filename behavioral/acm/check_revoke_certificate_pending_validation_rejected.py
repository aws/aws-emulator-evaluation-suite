"""revoke-certificate-pending-validation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "revoke-certificate-pending-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RevokeCertificate is refused while a certificate is still PENDING_VALIDATION (non-revocable status)."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    domain = _domain(ctx, "revokereject")
    arn = acm.request_certificate(
        DomainName=domain, ValidationMethod="DNS", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d["Status"] == "PENDING_VALIDATION",
        timeout_s=30.0,
    )
    assert desc["Status"] == "PENDING_VALIDATION", desc["Status"]

    try:
        acm.revoke_certificate(CertificateArn=arn, RevocationReason="UNSPECIFIED")
        raise AssertionError("RevokeCertificate must be rejected for a PENDING_VALIDATION certificate")
    except ClientError as err:
        # RevokeCertificate only accepts certificates that have already been issued and exported; a
        # certificate that is still PENDING_VALIDATION (and so has never been issued or exported) is
        # rejected by real ACM as a basic eligibility/validation failure -- ConflictException (which
        # ACM reserves for a resource that is already being concurrently created/updated) is not
        # what's returned here, ValidationException is.
        assert err.response["Error"]["Code"] == "ValidationException", err.response["Error"]["Code"]
        expected = f"Export not allowed for certificate {arn}"
        message = err.response["Error"].get("Message")
        assert message == expected, f"expected {expected!r}, got {message!r}"

    after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert after["Status"] == "PENDING_VALIDATION", "rejected revoke must not have changed certificate status"
    assert "RevokedAt" not in after, after.get("RevokedAt")

    # Differential control: a well-formed but nonexistent certificate ARN must be rejected with a
    # DIFFERENT, specific error (ResourceNotFoundException) -- this is what separates "rejects a
    # PENDING_VALIDATION certificate specifically" from "rejects every RevokeCertificate call".
    fake_arn = _fake_certificate_arn(ctx)
    try:
        acm.revoke_certificate(CertificateArn=fake_arn, RevocationReason="UNSPECIFIED")
        raise AssertionError("RevokeCertificate must be rejected for a nonexistent certificate ARN")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", err.response["Error"]["Code"]
        expected = f"Could not find certificate {fake_arn}."
        message = err.response["Error"].get("Message")
        assert message == expected, f"expected {expected!r}, got {message!r}"


# A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
# FAILED within seconds, while this one stays PENDING_VALIDATION for its 72-hour window.
def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.com"


def _fake_certificate_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:acm:{ctx.region}:{account_id}:certificate/00000000-0000-0000-0000-000000000000"


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe_delete(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
