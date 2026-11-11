"""acme-domain-validation-delete-then-describe-404."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-domain-validation-delete-then-describe-404"
GROUP = "error-semantics"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteAcmeDomainValidation, Describe eventually raises ResourceNotFoundException,
    the entry drops out of ListAcmeDomainValidations, and UpdateAcmeDomainValidation on the
    deleted arn fails the same way rather than resurrecting it."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)

    domain_name = f"{ctx.unique_name('sim2real-acmedv-').lower()}.example.com"
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )["AcmeDomainValidationArn"]

    # Positive control: the record is live and describable before deletion.
    live = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert live["Status"] in _LIVE_STATUSES, live["Status"]

    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)

    # Poll until the record is gone; it must never come back as fresh VALIDATING data.
    final_code = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            snap = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
            assert snap["Status"] == "DELETING", (
                f"expected DELETING or gone, got stale status {snap['Status']!r}"
            )
        except ClientError as exc:
            final_code = exc.response.get("Error", {}).get("Code")
            final_message = exc.response.get("Error", {}).get("Message")
            if final_code:
                break
        time.sleep(3)

    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after deletion, got {final_code!r}"
    )
    assert final_message == f"Could not find ACME domain validation {live['AcmeDomainValidationArn']}.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {final_message!r}"
    )

    listed = acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn)["AcmeDomainValidations"]
    assert all(dv["AcmeDomainValidationArn"] != dv_arn for dv in listed), (
        "deleted domain validation still present in ListAcmeDomainValidations"
    )

    # A mutation on the dead id must fail the same way an independent read does,
    # not silently resurrect or reconfigure a record that no longer exists.
    try:
        acm.update_acme_domain_validation(
            AcmeDomainValidationArn=dv_arn,
            PrevalidationOptions={"DnsPrevalidation": {}},
        )
        raise AssertionError("UpdateAcmeDomainValidation on a deleted arn unexpectedly succeeded")
    except ClientError as exc:
        update_code = exc.response.get("Error", {}).get("Code")
        update_message = exc.response.get("Error", {}).get("Message")
        assert update_code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from UpdateAcmeDomainValidation on a deleted "
            f"domain validation, got {update_code!r}"
        )
        assert update_message == f"Could not find ACME domain validation {live['AcmeDomainValidationArn']}.", (
            f"expected the exact ResourceNotFoundException message AWS returns, got {update_message!r}"
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
