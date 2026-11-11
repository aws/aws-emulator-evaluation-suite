"""create-acme-endpoint-duplicate-name-conflict."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-acme-endpoint-duplicate-name-conflict"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAcmeEndpoint retried with a used IdempotencyToken but different parameters is rejected
    with ConflictException and leaves the original unchanged; the same parameters return the same ARN."""
    acm = ctx.client("acm")
    token = ctx.unique_name("sim2real-acme-tok-")
    name = ctx.unique_name("sim2real-acme-ep-")
    resource_tags = [{"Key": "Name", "Value": name}]

    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        IdempotencyToken=token,
        Tags=resource_tags,
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _wait_for_endpoint_terminal(ctx, arn)

    def _conflicting_retry():
        return acm.create_acme_endpoint(
            AuthorizationBehavior="PRE_APPROVED",
            CertificateAuthority={"PublicCertificateAuthority": {}},
            Contact="REQUIRED",  # differs from the original call above
            IdempotencyToken=token,
            Tags=resource_tags,
        )

    code, message = _error_code(_conflicting_retry)
    assert code == "ConflictException", f"expected ConflictException, got {code} ({message!r})"
    expected_message = "Idempotency token was already used with different request parameters"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original endpoint's Contact setting was not overwritten
    described = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert described["Contact"] == "NOT_REQUIRED", (
        f"conflicting retry must not mutate the original endpoint, got Contact={described['Contact']!r}"
    )

    # restore: retrying with the *same* parameters as the original call is idempotent
    same_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        IdempotencyToken=token,
        Tags=resource_tags,
    )["AcmeEndpointArn"]
    assert same_arn == arn, f"identical retry with the same token must be idempotent, got {same_arn!r} != {arn!r}"

    # terminal read: independent of the create call above, confirms the idempotent
    # retry neither minted a second resource nor mutated the original's configuration
    final = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert final["AcmeEndpointArn"] == arn and final["Contact"] == "NOT_REQUIRED", (
        f"expected the original endpoint unchanged after the idempotent retry, got {final!r}"
    )


def _error_code(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so a target accepting a call AWS refuses is reported as an acceptance."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ConflictException, but the call SUCCEEDED and returned {result!r}")


def _wait_for_endpoint_terminal(
    ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> dict[str, Any]:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    endpoint: dict[str, Any] = {}
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if endpoint["Status"] in ("ACTIVE", "FAILED"):
            if endpoint["Status"] != "ACTIVE":
                raise AssertionError(
                    f"endpoint entered FAILED: {endpoint.get('FailureReason')}"
                )
            return endpoint
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} stayed CREATING past {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
