"""acme-endpoint-duplicate-create-conflicts."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "acme-endpoint-duplicate-create-conflicts"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing the same IdempotencyToken with identical parameters is idempotent (positive
    control: same ARN, no new resource), but reusing it with DIFFERENT parameters raises
    ConflictException and leaves the original endpoint's configuration untouched."""
    acm = ctx.client("acm")
    token = ctx.unique_name("acme-dup-")

    first = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        IdempotencyToken=token,
        Tags=[{"Key": "sim2real-check", "Value": token}],
    )
    arn = first["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _poll_until_active(ctx, arn)

    # Positive control: identical retry with the same token succeeds idempotently, returning
    # the SAME ArnEndpoint rather than creating a second resource. Every parameter of the first
    # call must be repeated, Tags included: real AWS compares the WHOLE request against the one
    # the token was minted for and answers a differing retry with
    # "Idempotency token was already used with different request parameters", the same
    # ConflictException the negative leg below asserts.
    retry = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        IdempotencyToken=token,
        Tags=[{"Key": "sim2real-check", "Value": token}],
    )
    assert retry["AcmeEndpointArn"] == arn, "identical retry with same token must be idempotent"

    # Negative: same token, different Contact -> ConflictException, no mutation of the original.
    code, message = _error_code(
        lambda: acm.create_acme_endpoint(
            AuthorizationBehavior="PRE_APPROVED",
            CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
            Contact="REQUIRED",
            IdempotencyToken=token,
        )
    )
    assert code == "ConflictException", f"expected ConflictException for mismatched idempotent retry, got {code!r}"
    expected_message = "Idempotency token was already used with different request parameters"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unaffected = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert unaffected["Contact"] == "NOT_REQUIRED", "failed conflicting create must not mutate the original endpoint"


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until_active(ctx, arn, timeout_s=120.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if last["Status"] == "ACTIVE":
            return last
        if last["Status"] == "FAILED":
            raise AssertionError(f"endpoint {arn} reached FAILED: {last.get('FailureReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached ACTIVE, last status={last and last['Status']}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
