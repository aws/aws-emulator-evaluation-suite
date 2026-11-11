"""list-certificate-domain-validations-reflects-pending."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-certificate-domain-validations-reflects-pending"
GROUP = "listing"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCertificateDomainValidations reports the same DNS validation state DescribeCertificate exposes."""
    acm = ctx.client("acm")
    domain = _domain(ctx, "listdomval")
    arn = acm.request_certificate(
        DomainName=domain, ValidationMethod="DNS", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    # Real ACM's DomainValidationSummary (the ListCertificateDomainValidations response shape) does not
    # necessarily populate its per-domain method/status/challenge details the instant the summary entry
    # itself appears, so poll until the pending status is actually reflected somewhere in the entry
    # rather than just until the list is non-empty. Do not assume a particular nesting for those
    # fields (e.g. a top-level "ValidationStatus" vs. a nested configuration object) -- just require
    # that the PENDING_VALIDATION status has shown up in the entry.
    summaries = _poll_until(
        lambda: acm.list_certificate_domain_validations(CertificateArn=arn)["DomainValidationSummaryList"],
        lambda s: s and _contains_value(s[0], "PENDING_VALIDATION"),
        timeout_s=120.0,
    )
    assert len(summaries) == 1, summaries
    summary = summaries[0]
    assert summary["DomainName"] == domain, summary["DomainName"]
    # A certificate requested directly with DNS validation carries its pending configuration in
    # RequestedValidationConfiguration or ActiveValidationConfiguration (the modeled members).
    config = next(
        (summary[key] for key in ("ActiveValidationConfiguration", "RequestedValidationConfiguration") if summary.get(key)),
        None,
    )
    assert config is not None, f"expected a validation configuration, got {summary!r}"
    assert config.get("ValidationMethod") == "DNS", f"ValidationMethod {config.get('ValidationMethod')!r} in {summary!r}"
    assert config.get("ValidationStatus") == "PENDING_VALIDATION", (
        f"ValidationStatus {config.get('ValidationStatus')!r} in {summary!r}"
    )

    # The docstring's claim ("reports the same DNS validation state DescribeCertificate
    # exposes") was previously untested -- assert the cross-check against the independent
    # DescribeCertificate read instead of just against ListCertificateDomainValidations' own
    # response.
    described = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert described["Status"] == "PENDING_VALIDATION", described["Status"]
    described_option = described["DomainValidationOptions"][0]
    assert described_option["DomainName"] == domain, described_option["DomainName"]
    assert described_option["ValidationStatus"] == "PENDING_VALIDATION", described_option["ValidationStatus"]
    assert described_option["ValidationMethod"] == config["ValidationMethod"], (
        f"DescribeCertificate ValidationMethod {described_option['ValidationMethod']!r}, "
        f"list {config['ValidationMethod']!r}"
    )


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    # Avoid RFC 2606 reserved second-level domains such as example.com/.net/.org: real ACM treats
    # requests for those (and their subdomains) as never-fully-validatable and does not populate the
    # per-domain validation challenge details (DNS resource record, validation emails, nested
    # validation-configuration status) even though the certificate request itself is accepted.
    return f"{label}.acmqa.co"


def _contains_value(obj, target: str) -> bool:
    if isinstance(obj, dict):
        return any(_contains_value(v, target) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_contains_value(v, target) for v in obj)
    return obj == target or (isinstance(obj, str) and target in obj)


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
