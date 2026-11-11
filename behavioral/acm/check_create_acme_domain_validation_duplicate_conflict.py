"""create-acme-domain-validation-duplicate-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-acme-domain-validation-duplicate-conflict"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateAcmeDomainValidation for the same domain on the same endpoint is a ConflictException."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_status(ctx, endpoint_arn, {"ACTIVE"})

    domain = f"{ctx.unique_name('sim2real-acme-dup-').rstrip('-').lower()}.example.com"
    first = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )
    dv_arn = first["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation(ctx, dv_arn))

    code, message = _error(
        lambda: acm.create_acme_domain_validation(
            AcmeEndpointArn=endpoint_arn,
            DomainName=domain,
            PrevalidationOptions={"DnsPrevalidation": {}},
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == f"An ACME domain validation for {domain} already exists.", message

    # effect absent: exactly one domain validation exists for this domain, not two, and it is
    # still the original record -- the rejected call left it untouched
    listed = acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn)["AcmeDomainValidations"]
    matching = [d for d in listed if d["DomainName"] == domain]
    assert len(matching) == 1, f"expected exactly one domain validation for {domain}, found {len(matching)}"
    assert matching[0]["AcmeDomainValidationArn"] == dv_arn, (
        f"expected the surviving record to be the original {dv_arn!r}, "
        f"got {matching[0]['AcmeDomainValidationArn']!r}"
    )

    # positive control: a distinct domain on the same endpoint is accepted
    other_domain = f"{ctx.unique_name('sim2real-acme-ctrl-').rstrip('-').lower()}.example.com"
    second = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=other_domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )
    other_dv_arn = second["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation(ctx, other_dv_arn))
    assert other_dv_arn != dv_arn, (
        f"expected a distinct-domain create to mint a new ARN, got the original {dv_arn!r} back"
    )

    # restore: the conflict is keyed on the (endpoint, domain) pair's live state, not the domain
    # string forever -- deleting the original record eventually frees it, and the identical call
    # then succeeds. Deletion is asynchronous on real AWS (describe transiently reports DELETING
    # before raising ResourceNotFoundException), so this is a bounded poll, not a single read.
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    deleted_code, deleted_message = _wait_for_domain_validation_deleted(ctx, dv_arn)
    assert deleted_code == "ResourceNotFoundException", (
        f"expected the deleted domain validation to become not-found, got {deleted_code!r}"
    )
    assert deleted_message == f"Could not find ACME domain validation {dv_arn}.", deleted_message

    restored = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )
    restored_arn = restored["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation(ctx, restored_arn))
    assert restored_arn != dv_arn, (
        f"expected the restored validation to get a fresh ARN, not the deleted {dv_arn!r}"
    )

    listed_after_restore = acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn)[
        "AcmeDomainValidations"
    ]
    matches_after_restore = [d for d in listed_after_restore if d["DomainName"] == domain]
    assert (
        len(matches_after_restore) == 1
        and matches_after_restore[0]["AcmeDomainValidationArn"] == restored_arn
    ), f"expected exactly one {domain} record pointing at the restored {restored_arn!r}, got {matches_after_restore}"


def _error(fn):
    """The (code, message) of the ClientError fn raises; a success is a mismatch."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, it succeeded")


def _create_acme_endpoint(ctx):
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-dup-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_acme_endpoint(ctx, arn))
    return arn


def _delete_acme_endpoint(ctx, arn):
    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _delete_domain_validation(ctx, arn):
    acm = ctx.client("acm")
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=arn)


def _wait_for_domain_validation_deleted(ctx, arn, timeout_s=60.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            snap = acm.describe_acme_domain_validation(AcmeDomainValidationArn=arn)["AcmeDomainValidation"]
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        last_status = snap["Status"]
        assert last_status == "DELETING", f"expected DELETING while draining, got stale status {last_status!r}"
        time.sleep(interval_s)
    raise AssertionError(f"domain validation {arn} never became not-found within {timeout_s}s, last status {last_status!r}")


def _wait_for_endpoint_status(ctx, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
