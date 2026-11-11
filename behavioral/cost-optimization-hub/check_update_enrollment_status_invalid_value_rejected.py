"""update-enrollment-status-invalid-value-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-enrollment-status-invalid-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["cost-optimization-hub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """UpdateEnrollmentStatus(status="Suspended") fails with ValidationException, its exact message and the
    enum field error, and leaves the status Active; a valid change to Inactive then shows in both the
    response and ListEnrollmentStatuses."""
    # cost-optimization-hub does not exist in ctx.region (us-west-2); pinned through
    # ctx.client(..., region=) rather than a bare boto3.client(), which would bypass the
    # check's own credentials and resolve the ambient chain instead.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # Create-or-adopt: an account that has never called UpdateEnrollmentStatus has no
    # item to read yet, so ListEnrollmentStatuses returns an empty list rather than IndexError-
    # ing on it. Only restore a prior status on cleanup; a first-time enrollment has none to
    # restore to.
    existing = coh.list_enrollment_statuses().get("items", [])
    original_status = existing[0]["status"] if existing else None
    if original_status is not None:
        ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))

    # Pin a known baseline (also enrolls the account on a first-time target) so we can assert
    # the invalid call had no side effect.
    coh.update_enrollment_status(status="Active")

    response = _client_error(lambda: coh.update_enrollment_status(status="Suspended"))
    code = response["Error"]["Code"]
    assert code == "ValidationException", (
        f'expected "ValidationException" rejecting status="Suspended", got {code!r}'
    )
    message = response["Error"].get("Message", "")
    expected_message = "Input validation failed. Please check the field list for more details."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"
    expected_fields = [
        {
            "fieldName": "status",
            "message": "Member must satisfy enum value set: [Active, Inactive, Failed]",
        }
    ]
    assert response.get("fields") == expected_fields, (
        f"expected fields {expected_fields!r}, got {response.get('fields')!r}"
    )

    unchanged = coh.list_enrollment_statuses()["items"][0]
    assert unchanged["status"] == "Active", (
        f'expected the rejected update to leave status "Active", got {unchanged["status"]!r}'
    )

    # Positive control: a genuinely valid transition still works in this file/session.
    control = coh.update_enrollment_status(status="Inactive")
    assert control["status"] == "Inactive", (
        f'expected the valid transition\'s own response to report "Inactive", got '
        f'{control["status"]!r}'
    )

    # Independent terminal read, at the destination: the mutating call's own response is not
    # the verdict, ListEnrollmentStatuses reflecting the transition is.
    final = _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Inactive",
        timeout_s=30.0,
    )
    assert final["status"] == "Inactive", (
        f'expected the valid transition visible at ListEnrollmentStatuses to be "Inactive", '
        f'got {final["status"]!r}'
    )


def _client_error(fn):
    """Call fn(); return its ClientError response. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
