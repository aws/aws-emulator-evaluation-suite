"""update-enrollment-status-pending-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-enrollment-status-pending-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """UpdateEnrollmentStatus only accepts status=Active|Inactive as input; Pending and
    Failed are output-only states of the enrollment state machine and must be rejected
    with InvalidParameterValueException, without mutating the account's enrollment status.
    """
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)

    baseline = co.get_enrollment_status()["status"]
    assert baseline == "Active", f"expected baseline enrollment status Active, got {baseline!r}"

    code, message = _error(lambda: co.update_enrollment_status(status="Pending"))
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException rejecting status=Pending, got {code!r}"
    )
    expected = "Invalid status, should be 'Active' or 'Inactive'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected call must not have mutated enrollment status
    after = co.get_enrollment_status()["status"]
    assert after == "Active", f"expected enrollment status unchanged at Active after rejected Pending call, got {after!r}"

    # positive control: a valid status value on the same operation still succeeds
    resp = co.update_enrollment_status(status="Active")
    assert resp["status"] == "Active", f"expected positive control update_enrollment_status(Active) to return Active, got {resp['status']!r}"

    # terminal read: independent of the mutating call, at the destination
    final = co.get_enrollment_status()["status"]
    assert final == "Active", f"expected GetEnrollmentStatus to independently confirm Active, got {final!r}"


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects status=Pending, but the call SUCCEEDED and returned {result!r}")


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    status = co.get_enrollment_status().get("status")
    if status != "Active":
        co.update_enrollment_status(status="Active")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached Active enrollment status, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
