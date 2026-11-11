"""get-query-status-wrong-monitor-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-query-status-wrong-monitor-rejected"
GROUP = "overly-permissive"
SERVICES = ["internetmonitor"]


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


def _wait_active(im, name, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = im.get_monitor(MonitorName=name)["Status"]
        if status == "ACTIVE":
            return
        time.sleep(2.0)
    raise AssertionError(f"monitor never became ACTIVE, status={status}")


def _safe_delete_monitor(im, name, timeout_s=60.0):
    """DeleteMonitor requires the monitor be INACTIVE first; transition it, then delete."""
    try:
        im.update_monitor(MonitorName=name, Status="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = im.get_monitor(MonitorName=name)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status == "INACTIVE":
            break
        time.sleep(2.0)
    im.delete_monitor(MonitorName=name)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an ACTIVE monitor, GetQueryStatus with a nonexistent QueryId fails with
    ValidationException "Invalid query ID provided", GetHealthEvent with a made-up EventId fails
    with ValidationException and its exact message, and the monitor stays ACTIVE."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-qa-")
    im.create_monitor(MonitorName=name, TrafficPercentageToMonitor=100, Tags={"team": "network-health"})
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))
    _wait_active(im, name)

    bogus_query_id = "00000000-0000-4000-8000-000000000000"
    code, message = _error(lambda: im.get_query_status(MonitorName=name, QueryId=bogus_query_id))
    assert code == "ValidationException", f"expected ValidationException for bogus QueryId, got: {code}"
    assert message == "Invalid query ID provided", f"unexpected message for bogus QueryId: {message!r}"

    bogus_event_id = "does-not-exist-event-id"
    code2, message2 = _error(lambda: im.get_health_event(MonitorName=name, EventId=bogus_event_id))
    assert code2 == "ValidationException", f"expected ValidationException for bogus EventId, got: {code2}"
    expected2 = f"resourceID is invalid: health-event/{name}/{bogus_event_id}"
    assert message2 == expected2, f"expected message {expected2!r} for bogus EventId, got {message2!r}"

    # Positive control: the monitor itself is real and reachable.
    still_there = im.get_monitor(MonitorName=name)
    assert still_there["Status"] == "ACTIVE"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
