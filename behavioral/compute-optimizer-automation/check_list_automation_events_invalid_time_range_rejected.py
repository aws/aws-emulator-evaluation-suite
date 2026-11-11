"""list-automation-events-invalid-time-range-rejected."""
from __future__ import annotations

import datetime as dt
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-automation-events-invalid-time-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """ListAutomationEvents rejects a time window where startTimeInclusive is after endTimeExclusive."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    now = dt.datetime.now(dt.timezone.utc)
    earlier = now - dt.timedelta(days=7)
    later = now

    # Positive control: a well-ordered time window succeeds (regardless of how many events exist).
    ok = client.list_automation_events(
        startTimeInclusive=earlier, endTimeExclusive=later, maxResults=10
    )
    assert isinstance(ok["automationEvents"], list), (
        f"expected automationEvents to be a list on a well-ordered window, got {ok.get('automationEvents')!r}"
    )

    # Break exactly one thing: swap the bounds so start is after end.
    code, message = _client_error(
        lambda: client.list_automation_events(
            startTimeInclusive=later, endTimeExclusive=earlier, maxResults=10
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for startTimeInclusive after endTimeExclusive, got {code!r}"
    )
    assert message == "Start date must be before end date", f"unexpected message: {message!r}"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _ensure_enrolled(ctx) -> None:
    

    co = ctx.client("compute-optimizer")
    base_status = co.get_enrollment_status().get("status")
    if base_status != "Active":
        co.update_enrollment_status(status="Active", includeMemberAccounts=False)
        deadline0 = time.monotonic() + 120
        while time.monotonic() < deadline0:
            base_status = co.get_enrollment_status().get("status")
            if base_status == "Active":
                break
            if base_status == "Failed":
                raise AssertionError("compute-optimizer base enrollment failed")
            time.sleep(3)
        else:
            raise AssertionError(
                "compute-optimizer base enrollment did not reach Active within 120s",
            )

    client = ctx.client("compute-optimizer-automation")
    cfg = client.get_enrollment_configuration()
    if cfg["status"] == "Active":
        return
    if cfg["status"] in ("Inactive", "Pending", "Failed"):
        client.update_enrollment_configuration(status="Active")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        cfg = client.get_enrollment_configuration()
        if cfg["status"] == "Active":
            return
        if cfg["status"] == "Failed":
            raise AssertionError(f"account enrollment failed: {cfg.get('statusReason')}")
        time.sleep(2)
    raise AssertionError(
        "account did not reach Active Compute Optimizer Automation enrollment status "
        "within 60s of requesting UpdateEnrollmentConfiguration(status=Active)",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
