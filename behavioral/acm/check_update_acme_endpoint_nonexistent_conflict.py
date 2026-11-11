"""update-acme-endpoint-nonexistent-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-acme-endpoint-nonexistent-conflict"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAcmeEndpoint on a deleted endpoint is refused with ResourceNotFoundException (not
    ConflictException) and the exact message and does not resurrect it, while the same update on
    a live ACTIVE endpoint takes effect."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_status(ctx, endpoint_arn, {"ACTIVE"})
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    _wait_for_endpoint_gone(ctx, endpoint_arn)

    expected_message = f"Could not find ACME endpoint {endpoint_arn}."
    code, message = _error(lambda: acm.update_acme_endpoint(AcmeEndpointArn=endpoint_arn, Contact="NOT_REQUIRED"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the endpoint is still gone, not resurrected by the update attempt
    describe_code, describe_message = _error(lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn))
    assert describe_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {describe_code!r}"
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    # positive control: updating a live endpoint succeeds and the change is observable
    live_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_status(ctx, live_arn, {"ACTIVE"})
    acm.update_acme_endpoint(AcmeEndpointArn=live_arn, Contact="NOT_REQUIRED")
    updated = acm.describe_acme_endpoint(AcmeEndpointArn=live_arn)["AcmeEndpoint"]
    assert updated["Contact"] == "NOT_REQUIRED", f"expected Contact=NOT_REQUIRED, got {updated['Contact']!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_acme_endpoint(ctx):
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-uenc-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint(ctx, arn))
    return arn


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
