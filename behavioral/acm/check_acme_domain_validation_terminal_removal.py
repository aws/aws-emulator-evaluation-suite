"""acme-domain-validation-terminal-removal."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-domain-validation-terminal-removal"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteAcmeDomainValidation succeeds, DescribeAcmeDomainValidation returns ResourceNotFoundException."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)

    domain = f"{ctx.unique_name('sim2real-behav-dvr-').lower()}.example.com".replace("_", "-")
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={
            "DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED", "Subdomains": "DISABLED"}}
        },
    )["AcmeDomainValidationArn"]

    cleanup_state = {"deleted": False}

    def _cleanup():
        if not cleanup_state["deleted"]:
            acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)

    ctx.on_cleanup(_cleanup)

    # Positive control: describable while it exists.
    desc = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert desc["AcmeDomainValidationArn"] == dv_arn, f"expected {dv_arn}, got {desc.get('AcmeDomainValidationArn')}"

    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    cleanup_state["deleted"] = True

    code, message = _poll_for_error_code(
        lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn), timeout_s=60
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Could not find ACME domain validation {dv_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A mutation on the dead id must also fail, not just the read: the gone-ness is not
    # a Describe-only artifact of a stale cache entry.
    update_code, update_message = _error_code(
        lambda: acm.update_acme_domain_validation(
            AcmeDomainValidationArn=dv_arn,
            PrevalidationOptions={"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED"}}},
        )
    )
    assert update_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {update_code}"
    assert update_message == expected_message, f"expected message {expected_message!r}, got {update_message!r}"


def _create_active_endpoint(ctx, acm):
    name = ctx.unique_name("sim2real-behav-acme-ep-")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": name}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    _wait_for_status(acm, arn, {"ACTIVE", "FAILED"}, timeout_s=90)
    return arn


def _wait_for_status(acm, arn, terminal_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    return last


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_for_error_code(fn, timeout_s=60.0, interval_s=2.0):
    """Poll fn() until it is refused; return the refusal's (code, message), raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call kept succeeding for {timeout_s}s after the delete")


def _best_effort(fn):
    fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
