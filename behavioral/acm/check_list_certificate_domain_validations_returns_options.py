"""list-certificate-domain-validations-returns-options."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-certificate-domain-validations-returns-options"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCertificateDomainValidations returns one summary for a DNS-validated request with a
    PENDING_VALIDATION CNAME challenge, matching DescribeCertificate's pending state."""
    acm = ctx.client("acm")
    # ACM fails validation for reserved domains such as example.com (DOMAIN_NOT_ALLOWED) within a
    # minute, which would end the pending state this check asserts on.
    domain = f"{ctx.unique_name('sim2real-acm-dv-')}.com".replace("_", "-")

    arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))

    # A cert requested directly with DNS validation carries its challenge under
    # RequestedValidationConfiguration; Active is populated only once in effect.
    def _challenge_config(summary):
        for key in ("ActiveValidationConfiguration", "RequestedValidationConfiguration"):
            config = summary.get(key) or {}
            challenge = config.get("ValidationChallenge")
            # ValidationChallenge appears empty before its CNAME record lands; wait for the record.
            if challenge and _find_resource_record(challenge) is not None:
                return config
        return None

    summaries = _poll_until(
        lambda: acm.list_certificate_domain_validations(CertificateArn=arn).get(
            "DomainValidationSummaryList", []
        ),
        lambda summaries: len(summaries) == 1 and _challenge_config(summaries[0]),
        timeout_s=60.0,
        interval_s=2.0,
    )

    assert len(summaries) == 1, f"expected 1 domain validation summary, got {len(summaries)}"
    summary = summaries[0]
    assert summary["DomainName"] == domain, f"expected DomainName {domain!r}, got {summary['DomainName']!r}"

    config = _challenge_config(summary)
    assert config is not None, f"expected a pending DNS challenge, got {summary!r}"
    assert config["ValidationMethod"] == "DNS", f"expected ValidationMethod DNS, got {config['ValidationMethod']!r}"
    assert config["ValidationStatus"] == "PENDING_VALIDATION", (
        f"expected ValidationStatus PENDING_VALIDATION, got {config['ValidationStatus']!r}"
    )

    dns_challenge = config["ValidationChallenge"]["DnsValidationChallenge"]
    # The CNAME fields are not under a fixed "ResourceRecord" key here, so find them structurally.
    record = _find_resource_record(dns_challenge)
    assert record is not None, (
        f"expected a CNAME resource record in DnsValidationChallenge, got {dns_challenge!r}"
    )
    assert record["Type"] == "CNAME", f"expected CNAME resource record, got Type={record['Type']!r}"
    assert record["Name"], "expected a non-empty CNAME record name to publish"
    assert record["Value"], "expected a non-empty CNAME record value to publish"

    # DescribeCertificate cross-checks the same pending state independently.
    described = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert described["Status"] == "PENDING_VALIDATION", (
        f"expected DescribeCertificate Status PENDING_VALIDATION, got {described['Status']!r}"
    )
    described_status = described["DomainValidationOptions"][0]["ValidationStatus"]
    assert described_status == "PENDING_VALIDATION", (
        f"expected DescribeCertificate DomainValidationOptions[0].ValidationStatus "
        f"PENDING_VALIDATION, got {described_status!r}"
    )


def _find_resource_record(node: Any) -> dict | None:
    if isinstance(node, dict):
        if {"Name", "Type", "Value"} <= node.keys():
            return node
        for value in node.values():
            found = _find_resource_record(value)
            if found is not None:
                return found
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
