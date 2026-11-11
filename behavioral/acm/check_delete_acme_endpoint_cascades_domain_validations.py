"""delete-acme-endpoint-cascades-domain-validations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-acme-endpoint-cascades-domain-validations"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an ACME endpoint cascades: its dependent domain validation is removed too, so
    DescribeAcmeDomainValidation transitions to ResourceNotFoundException once the parent
    endpoint is deleted, even though it was never explicitly deleted itself."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)

    domain = _domain_name(ctx, "dv-cascade")
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )["AcmeDomainValidationArn"]

    # confirm it is alive and attached to this endpoint before the cascade
    described = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert described["AcmeEndpointArn"] == endpoint_arn, (
        f"domain validation {dv_arn} reports parent endpoint {described['AcmeEndpointArn']!r}, "
        f"expected {endpoint_arn!r}"
    )

    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)

    _poll_until_not_found(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn),
        f"Could not find ACME endpoint {endpoint_arn}.",
    )
    _poll_until_not_found(
        lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn),
        f"Could not find ACME domain validation {dv_arn}.",
    )

    # DeleteAcmeEndpoint and DeleteAcmeDomainValidation are idempotent: repeating either on an
    # already-removed resource succeeds silently instead of raising ResourceNotFoundException.
    # A ClientError from either repeat delete propagates and fails the check.
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)


def _ignore(fn) -> None:
    fn()


def _domain_name(ctx, label: str) -> str:
    token = ctx.unique_name(f"sim2real-{label}-").lower().strip("-")
    return f"{token}.example.com"


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _poll_until_not_found(describe_fn, expected_message: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    """Poll describe_fn() until it raises; the refusal must be ResourceNotFoundException
    carrying exactly expected_message."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe_fn()
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
            assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code} ({message!r})"
            assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
            return
        time.sleep(interval_s)
    raise AssertionError(f"resource still describable {timeout_s}s after cascade delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
