"""create-acme-domain-validation-duplicate-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-acme-domain-validation-duplicate-rejected"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateAcmeDomainValidation for a domain with an active validation is rejected with
    ConflictException and leaves the original alone; a different domain succeeds, and after the
    original is deleted the identical call succeeds."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)

    domain_a = _domain_name(ctx, "dv-dup-a")
    domain_b = _domain_name(ctx, "dv-dup-b")
    dv_a_tags = [{"Key": "Name", "Value": domain_a}]

    dv_a_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_a,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=dv_a_tags,
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _cleanup_delete(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_a_arn)))

    # break exactly one thing: create a second validation for the SAME domain on the SAME endpoint
    code, message = _error_code(
        lambda: acm.create_acme_domain_validation(
            AcmeEndpointArn=endpoint_arn,
            DomainName=domain_a,
            PrevalidationOptions={"DnsPrevalidation": {}},
            Tags=dv_a_tags,
        )
    )
    assert code == "ConflictException", f"expected ConflictException for duplicate domain, got {code}"
    expected_message = f"An ACME domain validation for {domain_a} already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: exactly one validation for domain_a exists, unaffected by the rejected attempt
    matches = [dv for dv in _list_domain_validations(acm, endpoint_arn) if dv["DomainName"] == domain_a]
    assert len(matches) == 1, f"expected exactly 1 validation for {domain_a}, found {len(matches)}: {matches}"
    assert matches[0]["AcmeDomainValidationArn"] == dv_a_arn, (
        f"expected the surviving validation to be the original {dv_a_arn}, found {matches[0]['AcmeDomainValidationArn']}"
    )

    # positive control: a different domain on the same endpoint is unaffected and succeeds
    dv_b_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_b,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "Name", "Value": domain_b}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _cleanup_delete(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_b_arn)))
    assert dv_b_arn != dv_a_arn, f"positive control minted the same ARN as the original: {dv_b_arn}"

    # restore: delete the original validation, then the identical (endpoint, domain) call that was
    # just rejected must now succeed -- the conflict is tied to the existing record's lifecycle,
    # not a permanent block on the domain string. Deletion is asynchronous (the record passes
    # through DELETING before DescribeAcmeDomainValidation starts raising ResourceNotFoundException),
    # so wait for that transition on a bounded retry rather than assuming it is instant.
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_a_arn)
    gone_message = _wait_for_domain_validation_gone(acm, dv_a_arn)
    expected_gone = f"Could not find ACME domain validation {dv_a_arn}."
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    # independent read: the deleted validation is gone before the retry
    after_delete = [dv for dv in _list_domain_validations(acm, endpoint_arn) if dv["DomainName"] == domain_a]
    assert not after_delete, f"expected {domain_a} to have no validations after delete, found {after_delete}"

    dv_a2_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_a,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=dv_a_tags,
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _cleanup_delete(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_a2_arn)))
    assert dv_a2_arn != dv_a_arn, f"restored call minted the same ARN as the deleted original: {dv_a2_arn}"

    # terminal read: independent of the create call above, confirms exactly one (fresh) validation
    # for domain_a exists after the restore
    final_matches = [dv for dv in _list_domain_validations(acm, endpoint_arn) if dv["DomainName"] == domain_a]
    assert len(final_matches) == 1, f"expected exactly 1 validation for {domain_a} after restore, found {len(final_matches)}: {final_matches}"
    assert final_matches[0]["AcmeDomainValidationArn"] == dv_a2_arn, (
        f"expected the restored validation to be {dv_a2_arn}, found {final_matches[0]['AcmeDomainValidationArn']}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting a call AWS refuses is reported as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _cleanup_delete(fn):
    """Tolerant teardown: swallow ResourceNotFoundException (already gone, e.g. the restore leg
    deletes dv_a mid-test), but never swallow anything else."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _domain_name(ctx, label: str) -> str:
    token = ctx.unique_name(f"sim2real-{label}-").lower().strip("-")
    return f"{token}.example.com"


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    name = ctx.unique_name("sim2real-acme-ep-")
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "Name", "Value": name}],
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _cleanup_delete(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
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


def _wait_for_domain_validation_gone(acm, dv_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    """Poll Describe until it is refused with ResourceNotFoundException; return that message."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return exc.response["Error"].get("Message")
            raise
        time.sleep(interval_s)
    raise AssertionError(f"{dv_arn} never disappeared within {timeout_s}s, last status={last_status}")


def _list_domain_validations(acm, endpoint_arn: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"AcmeEndpointArn": endpoint_arn}
        if token:
            kwargs["NextToken"] = token
        resp = acm.list_acme_domain_validations(**kwargs)
        out.extend(resp.get("AcmeDomainValidations", []))
        token = resp.get("NextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
