"""acme-endpoint-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-endpoint-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeEndpoint yields a describable ACTIVE endpoint; after DeleteAcmeEndpoint,
    DescribeAcmeEndpoint fails with ResourceNotFoundException and a mutation on the dead
    ARN (UpdateAcmeEndpoint) fails the same way rather than resurrecting it."""
    acm = ctx.client("acm")
    arn = _create_acme_endpoint(ctx)

    described = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert described["AcmeEndpointArn"] == arn, (
        f"expected AcmeEndpointArn {arn}, got {described.get('AcmeEndpointArn')!r}"
    )
    assert described["Status"] == "ACTIVE", f"expected Status ACTIVE, got {described['Status']!r}"
    assert described["AuthorizationBehavior"] == "PRE_APPROVED", (
        f"expected AuthorizationBehavior PRE_APPROVED, got {described['AuthorizationBehavior']!r}"
    )
    assert described.get("EndpointUrl"), f"expected a non-empty EndpointUrl, got {described.get('EndpointUrl')!r}"

    acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    expected_message = f"Could not find ACME endpoint {arn}."
    gone_message = _wait_for_endpoint_gone(ctx, arn)
    assert gone_message == expected_message, f"expected message {expected_message!r}, got {gone_message!r}"

    try:
        acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact="REQUIRED")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from UpdateAcmeEndpoint on a deleted ARN, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(f"UpdateAcmeEndpoint on deleted endpoint {arn} unexpectedly succeeded")


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_ignore_errors(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _wait_for_endpoint_gone(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    """Poll Describe until it is refused with ResourceNotFoundException; return that message."""
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return e.response["Error"].get("Message")
            raise
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} still describable after {timeout_s}s")


def _delete_endpoint_ignore_errors(ctx, arn: str) -> None:
    acm = ctx.client("acm")
    try:
        acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code != "ResourceNotFoundException":
            raise AssertionError(f"cleanup delete of {arn} failed unexpectedly: {code}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
