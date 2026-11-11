"""request-certificate-email-validation-domain-options."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "request-certificate-email-validation-domain-options"
GROUP = "lifecycle"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EMAIL-validated requests get the five standard role-account addresses for the domain."""
    acm = ctx.client("acm")
    domain = _domain(ctx, "emailval")
    arn = acm.request_certificate(
        DomainName=domain, ValidationMethod="EMAIL", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    # Real ACM can take noticeably longer than a couple of minutes to compute and attach the
    # role-account validation email list to a freshly requested certificate; use a generous bound,
    # but stay well under the harness's overall check timeout (300s) so a slow-but-eventually-
    # successful poll does not get killed as a hard timeout instead of surfacing a real assertion
    # failure.
    desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("DomainValidationOptions") and d["DomainValidationOptions"][0].get("ValidationEmails"),
        timeout_s=240.0,
        interval_s=5.0,
    )
    option = desc["DomainValidationOptions"][0]
    assert option["ValidationMethod"] == "EMAIL", option["ValidationMethod"]
    assert option["ValidationDomain"] == domain, option["ValidationDomain"]
    expected = {f"{role}@{domain}" for role in ("admin", "administrator", "hostmaster", "postmaster", "webmaster")}
    assert set(option["ValidationEmails"]) == expected, option["ValidationEmails"]


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
