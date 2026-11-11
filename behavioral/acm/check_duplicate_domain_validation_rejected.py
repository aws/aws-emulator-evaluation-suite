"""duplicate-domain-validation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-domain-validation-rejected"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second ACME domain validation for the same domain on one endpoint is refused with
    ConflictException and its exact message, leaving one record; a different domain succeeds, and
    the same domain succeeds again once the original is deleted."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)

    domain = f"{ctx.unique_name('sim2real-acmedup-')}.example.com".lower()
    other_domain = f"{ctx.unique_name('sim2real-acmeother-')}.example.com".lower()
    scope = {"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "DISABLED"}}}

    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn, DomainName=domain, PrevalidationOptions=scope
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))
    )

    # Break exactly one thing: request the exact same domain again on the exact same endpoint.
    code, message = _error(
        lambda: acm.create_acme_domain_validation(
            AcmeEndpointArn=endpoint_arn, DomainName=domain, PrevalidationOptions=scope
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected_message = f"An ACME domain validation for {domain} already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect must be absent: exactly one domain validation exists for `domain` on this endpoint.
    matches = [
        dv
        for dv in acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn).get("AcmeDomainValidations", [])
        if dv["DomainName"] == domain
    ]
    assert len(matches) == 1, f"expected exactly one domain validation for {domain}, found {len(matches)}"
    assert matches[0]["AcmeDomainValidationArn"] == dv_arn

    # Positive control: a validation for a *different* domain on the same endpoint succeeds.
    other_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn, DomainName=other_domain, PrevalidationOptions=scope
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=other_arn))
    )
    assert other_arn != dv_arn
    described = acm.describe_acme_domain_validation(AcmeDomainValidationArn=other_arn)["AcmeDomainValidation"]
    assert described["DomainName"] == other_domain

    # Restore: the conflict is keyed on the still-live original record, not a permanent block on
    # the domain string. Delete the original, confirm it is actually gone (not merely DELETING),
    # then the identical (endpoint, domain) call that was rejected above must now succeed.
    # A delete during VALIDATING is refused as a concurrent modification; example.com never
    # validates, so wait for the record to settle first.
    _poll_until(
        lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]["Status"],
        lambda status: status not in ("VALIDATING", "PENDING"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    _wait_until_gone(lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn))

    restored_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn, DomainName=domain, PrevalidationOptions=scope
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=restored_arn))
    )
    assert restored_arn != dv_arn, "restored validation reused the deleted ARN"
    restored = acm.describe_acme_domain_validation(AcmeDomainValidationArn=restored_arn)["AcmeDomainValidation"]
    assert restored["DomainName"] == domain


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_until_gone(describe_fn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = describe_fn()["AcmeDomainValidation"]["Status"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            raise AssertionError(f"unexpected error while waiting for deletion: {code}")
        time.sleep(interval_s)
    raise AssertionError(f"domain validation still present after {timeout_s}s, last status={last_status!r}")


def _create_active_endpoint(ctx, acm):
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
