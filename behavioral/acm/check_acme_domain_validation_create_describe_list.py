"""acme-domain-validation-create-describe-list."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-domain-validation-create-describe-list"
GROUP = "state-machine"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeDomainValidation makes the record visible via Describe and List with its arn,
    endpoint, domain and DNS prevalidation type, in a live VALIDATING, VALID or INVALID status."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)

    domain_name = f"{ctx.unique_name('sim2real-acmedv-').lower()}.example.com"
    create_resp = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )
    dv_arn = create_resp["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation_quiet(ctx, dv_arn))

    # ARN shape: the domain validation ARN is scoped under the endpoint ARN.
    assert dv_arn.startswith(endpoint_arn + "/acme-domain-validation/"), dv_arn

    described = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert described["AcmeDomainValidationArn"] == dv_arn, (
        f"expected AcmeDomainValidationArn={dv_arn!r}, got {described['AcmeDomainValidationArn']!r}"
    )
    assert described["AcmeEndpointArn"] == endpoint_arn, (
        f"expected AcmeEndpointArn={endpoint_arn!r}, got {described['AcmeEndpointArn']!r}"
    )
    assert described["DomainName"] == domain_name, (
        f"expected DomainName={domain_name!r}, got {described['DomainName']!r}"
    )
    assert described["Status"] in _LIVE_STATUSES, described["Status"]
    # Real AWS reports the prevalidation type as the short enum value "DNS"
    # (not the config key "DNS_PREVALIDATION"/"DnsPrevalidation").
    assert described["PrevalidationType"] == "DNS", described["PrevalidationType"]

    listed = acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn)["AcmeDomainValidations"]
    matches = [dv for dv in listed if dv["AcmeDomainValidationArn"] == dv_arn]
    assert len(matches) == 1, f"expected exactly 1 matching entry in list, got {len(matches)}"
    assert matches[0]["DomainName"] == domain_name, (
        f"expected DomainName={domain_name!r}, got {matches[0]['DomainName']!r}"
    )
    assert matches[0]["Status"] in _LIVE_STATUSES, matches[0]["Status"]


def _create_acme_endpoint(ctx: Any) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    endpoint_arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_quiet(ctx, endpoint_arn))
    return endpoint_arn


def _wait_for_endpoint_active(ctx: Any, endpoint_arn: str, timeout_s: float = 120.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
        if last["Status"] == "ACTIVE":
            return last
        if last["Status"] == "FAILED":
            raise AssertionError(f"ACME endpoint creation failed: {last.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint never reached ACTIVE within {timeout_s}s, last={last}")


def _delete_domain_validation_quiet(ctx: Any, dv_arn: str) -> None:
    acm = ctx.client("acm")
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)


def _delete_endpoint_quiet(ctx: Any, endpoint_arn: str) -> None:
    acm = ctx.client("acm")
    for attempt in range(10):
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and attempt < 9:
                time.sleep(3)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
