"""list-health-events-empty-for-new-monitor."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-health-events-empty-for-new-monitor"
GROUP = "events"
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHealthEvents on a monitor without resources is empty with no NextToken, GetHealthEvent
    with a made-up EventId fails with ValidationException and its exact message, and the monitor
    stays ACTIVE."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-health-")
    im.create_monitor(MonitorName=name, TrafficPercentageToMonitor=100, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))
    _wait_active(im, name)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    page = im.list_health_events(MonitorName=name, StartTime=start, EndTime=end)
    events = page["HealthEvents"]
    assert events == [], f"expected no health events for a fresh monitor, got: {events}"
    assert not page.get("NextToken"), (
        f"expected no pagination token for an empty page, got: {page.get('NextToken')!r}"
    )

    bogus_event_id = "00000000-0000-4000-8000-000000000000"
    code, message = _error(lambda: im.get_health_event(MonitorName=name, EventId=bogus_event_id))
    assert code == "ValidationException", f"expected ValidationException for a fabricated EventId, got: {code}"
    expected = f"resourceID is invalid: health-event/{name}/{bogus_event_id}"
    assert message == expected, f"expected message {expected!r} for a fabricated EventId, got {message!r}"

    # Positive control: the monitor itself is still real and reachable, so the negative above
    # isn't explained by the monitor being unreachable or the client being misconfigured.
    still_there = im.get_monitor(MonitorName=name)
    assert still_there["Status"] == "ACTIVE", f"expected monitor still ACTIVE, got: {still_there['Status']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
