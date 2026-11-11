"""update-acme-endpoint-missing-returns-conflict."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-acme-endpoint-missing-returns-conflict"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAcmeEndpoint on a deleted endpoint is refused with ResourceNotFoundException and the
    exact message and does not resurrect it, while the same update on a live endpoint persists."""
    acm = ctx.client("acm")
    dead_arn = _create_acme_endpoint(ctx)
    acm.delete_acme_endpoint(AcmeEndpointArn=dead_arn)
    _wait_for_endpoint_gone(ctx, dead_arn)

    expected_message = f"Could not find ACME endpoint {dead_arn}."
    code, message = _error(lambda: acm.update_acme_endpoint(AcmeEndpointArn=dead_arn, Contact="REQUIRED"))
    assert code == "ResourceNotFoundException", f"GOT={code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the failed update did not resurrect the endpoint
    describe_code, describe_message = _error(lambda: acm.describe_acme_endpoint(AcmeEndpointArn=dead_arn))
    assert describe_code == "ResourceNotFoundException", f"GOT={describe_code!r}"
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    # positive control: update against a live endpoint succeeds and is durable
    live_arn = _create_acme_endpoint(ctx, contact="NOT_REQUIRED")
    acm.update_acme_endpoint(AcmeEndpointArn=live_arn, Contact="REQUIRED")
    updated = acm.describe_acme_endpoint(AcmeEndpointArn=live_arn)["AcmeEndpoint"]
    assert updated["Contact"] == "REQUIRED", f"expected Contact=REQUIRED, got {updated['Contact']!r}"




def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-uemrc-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint(ctx, arn))
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


def _wait_for_endpoint_gone(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} still describable after {timeout_s}s")


def _delete_endpoint(ctx, arn: str) -> None:
    """Teardown: delete the endpoint, retrying the documented ConflictException while it is still
    settling; an endpoint that is already gone is accepted, anything else raises."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + min(120.0, ctx.time_left() or 120.0)
    while True:
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
