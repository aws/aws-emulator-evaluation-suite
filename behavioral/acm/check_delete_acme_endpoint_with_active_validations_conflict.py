"""delete-acme-endpoint-with-active-validations-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-acme-endpoint-with-active-validations-conflict"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeEndpoint reusing an IdempotencyToken with different parameters is rejected with
    ConflictException while the same parameters return the same endpoint, and DeleteAcmeEndpoint
    with an active domain validation succeeds and removes the validation with it."""
    acm = ctx.client("acm")
    token = ctx.unique_name("sim2real-acme-idem-")

    ca = {"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}}
    check_tags = [{"Key": "sim2real", "Value": CHECK}]

    first = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority=ca,
        Contact="NOT_REQUIRED",
        IdempotencyToken=token,
        Tags=check_tags,
    )
    endpoint_arn = first["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_acme_endpoint(ctx, endpoint_arn))
    _wait_for_endpoint_status(ctx, endpoint_arn, {"ACTIVE"})

    # reusing the same IdempotencyToken with a DIFFERENT Contact setting conflicts
    code, message = _error_code(
        lambda: acm.create_acme_endpoint(
            AuthorizationBehavior="PRE_APPROVED",
            CertificateAuthority=ca,
            Contact="REQUIRED",
            IdempotencyToken=token,
            Tags=check_tags,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r} ({message!r})"
    expected_message = "Idempotency token was already used with different request parameters"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no second endpoint was created; the original is unaffected (still NOT_REQUIRED)
    unaffected = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
    assert unaffected["Contact"] == "NOT_REQUIRED", (
        f"conflicting create must not mutate the original endpoint, got Contact={unaffected['Contact']!r}"
    )

    # positive control: reusing the same token with the SAME parameters is idempotent and
    # returns the very same endpoint, not a conflict
    replay = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority=ca,
        Contact="NOT_REQUIRED",
        IdempotencyToken=token,
        Tags=check_tags,
    )
    assert replay["AcmeEndpointArn"] == endpoint_arn, (
        f"identical retry with the same IdempotencyToken must be idempotent, "
        f"expected {endpoint_arn!r}, got {replay['AcmeEndpointArn']!r}"
    )

    # DeleteAcmeEndpoint is not blocked by an active domain validation; it removes the validation
    # with the endpoint.
    domain = f"{ctx.unique_name('sim2real-acme-del-').rstrip('-').lower()}.example.com"
    dv = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )
    dv_arn = dv["AcmeDomainValidationArn"]

    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    _wait_for_endpoint_gone(ctx, endpoint_arn)

    dv_code, dv_message = _error_code(lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn))
    assert dv_code == "ResourceNotFoundException", (
        f"expected the domain validation to be cascade-removed with its endpoint, got {dv_code!r}"
    )
    expected_message = f"Could not find ACME domain validation {dv_arn}."
    assert dv_message == expected_message, f"expected message {expected_message!r}, got {dv_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_acme_endpoint(ctx, arn):
    acm = ctx.client("acm")
    try:
        acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _wait_for_endpoint_gone(ctx, arn, timeout_s=90.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} was never fully removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

