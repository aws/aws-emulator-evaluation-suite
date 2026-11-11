"""describe-nonexistent-acme-domain-validation-rejected."""
from __future__ import annotations

import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-acme-domain-validation-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAcmeDomainValidation on a well-formed but unknown ARN raises ResourceNotFoundException,
    while an identical call against a real domain validation still succeeds — proving the rejection is
    keyed on the ARN, not on the operation being refused outright."""
    acm = ctx.client("acm")
    account = _account_id(ctx)

    # Positive control: a real domain validation describes successfully on this same wiring.
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)
    domain_name = f"{ctx.unique_name('sim2real-acmedv-').lower()}.example.com"
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation_quiet(ctx, dv_arn))

    live = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert live["Status"] in _LIVE_STATUSES, live["Status"]

    # Matches arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:acme-endpoint/[a-zA-Z0-9-]+/acme-domain-validation/[a-zA-Z0-9-]+
    fake_arn = (
        f"arn:aws:acm:{ctx.region}:{account}:acme-endpoint/{uuid.uuid4()}"
        f"/acme-domain-validation/{uuid.uuid4()}"
    )

    code, message = _error_code(lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=fake_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for unknown ACME domain validation, got {code!r}"
    )
    assert message == f"Could not find ACME domain validation {fake_arn}.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
