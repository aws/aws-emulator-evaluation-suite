"""acme-domain-validation-update-transitions-state."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-domain-validation-update-transitions-state"
GROUP = "state-machine"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAcmeDomainValidation changes the prevalidation config as reflected by a subsequent
    Describe, keeping the domain and endpoint and leaving the record in a live status."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)

    domain_name = f"{ctx.unique_name('sim2real-acmedv-').lower()}.example.com"
    initial_scope = {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "DISABLED"}
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": initial_scope}},
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation_quiet(ctx, dv_arn))

    before = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    before_scope = before["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
    assert before_scope["Subdomains"] == "DISABLED", before_scope
    assert before["Status"] in _LIVE_STATUSES, before["Status"]
    updated_at_before = before["UpdatedAt"]

    # UpdateAcmeDomainValidation rejects requests while the record is still in
    # VALIDATING status (ValidationException: "Cannot update ACME domain
    # validation in VALIDATING status."). With PRE_APPROVED authorization the
    # record settles out of VALIDATING quickly, so poll (bounded) until it
    # leaves that status before attempting the update.
    settled = _wait_until_not_validating(ctx, dv_arn)
    assert settled["Status"] != "VALIDATING", settled["Status"]


    new_scope = {"ExactDomain": "ENABLED", "Subdomains": "ENABLED", "Wildcards": "DISABLED"}
    acm.update_acme_domain_validation(
        AcmeDomainValidationArn=dv_arn,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": new_scope}},
    )

    after = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    after_scope = after["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
    assert after_scope["Subdomains"] == "ENABLED", after_scope
    assert after_scope["ExactDomain"] == "ENABLED", after_scope
    # Domain name and endpoint identity are unaffected by the config update.
    assert after["DomainName"] == domain_name, (after["DomainName"], domain_name)
    assert after["AcmeEndpointArn"] == endpoint_arn, (after["AcmeEndpointArn"], endpoint_arn)
    assert after["UpdatedAt"] >= updated_at_before, (after["UpdatedAt"], updated_at_before)
    # UpdateAcmeDomainValidation has no client-settable Status field; ACM may re-verify
    # the CNAME after the change and settle it again at any speed, so any live status holds.
    assert after["Status"] in _LIVE_STATUSES, (
        f"expected a live status after PrevalidationOptions change, got {after['Status']!r}"
    )


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


def _wait_until_not_validating(ctx: Any, dv_arn: str, timeout_s: float = 60.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
        if last["Status"] != "VALIDATING":
            return last
        time.sleep(3)
    raise AssertionError(f"ACME domain validation still VALIDATING after {timeout_s}s, last={last}")


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
