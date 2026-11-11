"""resend-validation-email-wrong-domain-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "resend-validation-email-wrong-domain-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResendValidationEmail succeeds for the certificate's own domain but is rejected for an unrelated domain."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    domain = _domain(ctx, "resendok")
    unrelated_domain = _domain(ctx, "resendbad")
    arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="EMAIL",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    # Real ACM can take noticeably longer than a couple of minutes to compute and attach the
    # role-account validation email list to a freshly requested certificate; use a generous bound,
    # but stay well under the harness's overall check timeout (300s) so a slow-but-eventually-
    # successful poll does not get killed as a hard timeout instead of surfacing a real assertion
    # failure.
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("DomainValidationOptions") and d["DomainValidationOptions"][0].get("ValidationEmails"),
        timeout_s=180.0,
        interval_s=5.0,
    )

    # Positive control: resending for the certificate's own (correct) domain succeeds.
    resp = acm.resend_validation_email(CertificateArn=arn, Domain=domain, ValidationDomain=domain)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    # Negative: an unrelated domain that is not on the certificate must be rejected.
    try:
        acm.resend_validation_email(
            CertificateArn=arn, Domain=unrelated_domain, ValidationDomain=unrelated_domain
        )
        raise AssertionError("ResendValidationEmail must be rejected for a domain not on the certificate")
    except ClientError as err:
        # Real ACM looks up the DomainValidationOptions entry matching the requested Domain; since
        # the unrelated domain has no such entry on the certificate, it raises
        # ResourceNotFoundException (not InvalidDomainValidationOptionsException, which is reserved
        # for e.g. a validation-domain/domain mismatch on an entry that does exist).
        assert (
            err.response["Error"]["Code"] == "ResourceNotFoundException"
        ), err.response["Error"]["Code"]
        account = arn.split(":")[4]
        expected = f"Could not find certificate {arn} with domain {unrelated_domain} in account {account}"
        message = err.response["Error"].get("Message")
        assert message == expected, f"expected {expected!r}, got {message!r}"

    # Independent read at the destination: the rejected call must not have added the unrelated
    # domain to the certificate's own validation-options list.
    after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    after_domains = {o["DomainName"] for o in after["DomainValidationOptions"]}
    assert unrelated_domain not in after_domains, after_domains


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    # Avoid RFC 2606 reserved second-level domains such as example.com: real ACM accepts a
    # RequestCertificate call for such a domain (and keeps the certificate in PENDING_VALIDATION), but
    # never populates the email-validation challenge details (ValidationEmails) in
    # DomainValidationOptions, so polling for it would spin forever. Use a domain that isn't on that
    # reserved list instead.
    return f"{label}.acmqa.co"


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
