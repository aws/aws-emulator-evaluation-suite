"""delete-monitor-removes-monitor."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-monitor-removes-monitor"
GROUP = "state"
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
    try:
        im.delete_monitor(MonitorName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteMonitor, the monitor disappears from ListMonitors, GetMonitor rejects the name, and
    UpdateMonitor against the dead id also fails."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-del-")
    im.create_monitor(MonitorName=name, TrafficPercentageToMonitor=100, Tags={"team": "network-health"})
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    # Wait for the monitor to leave PENDING before deleting (delete may reject mid-creation).
    deadline = time.monotonic() + 60.0
    status = None
    while time.monotonic() < deadline:
        status = im.get_monitor(MonitorName=name)["Status"]
        if status != "PENDING":
            break
        time.sleep(2.0)
    assert status == "ACTIVE", f"monitor never became ACTIVE before delete, status={status}"

    # DeleteMonitor requires the monitor to be INACTIVE first (empirically: ValidationException
    # "must be in inactive state" when deleting an ACTIVE monitor).
    im.update_monitor(MonitorName=name, Status="INACTIVE")
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        status = im.get_monitor(MonitorName=name)["Status"]
        if status == "INACTIVE":
            break
        time.sleep(2.0)
    assert status == "INACTIVE", f"monitor never became INACTIVE before delete, status={status}"

    im.delete_monitor(MonitorName=name)

    # Poll until the monitor is actually gone (deletion is asynchronous).
    gone = False
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        names = [m["MonitorName"] for m in im.list_monitors().get("Monitors", [])]
        if name not in names:
            gone = True
            break
        time.sleep(2.0)
    assert gone, "deleted monitor still present in ListMonitors after 60s"

    expected = f"No resource found for account {ctx.account} and resource monitor/{name}"
    code, message = _error(lambda: im.get_monitor(MonitorName=name))
    assert code == "ResourceNotFoundException", f"GetMonitor on deleted monitor returned unexpected code: {code}"
    assert message == expected, f"GetMonitor on deleted monitor: expected {expected!r}, got {message!r}"

    # A mutation against the dead id must also fail, not just a read.
    code, message = _error(lambda: im.update_monitor(MonitorName=name, Status="ACTIVE"))
    assert code == "ResourceNotFoundException", f"UpdateMonitor on deleted monitor returned unexpected code: {code}"
    assert message == expected, f"UpdateMonitor on deleted monitor: expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
