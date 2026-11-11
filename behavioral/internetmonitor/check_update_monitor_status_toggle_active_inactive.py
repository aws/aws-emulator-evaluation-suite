"""update-monitor-status-toggle-active-inactive."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-monitor-status-toggle-active-inactive"
GROUP = "state"
SERVICES = ["internetmonitor"]


def _wait_for_status(im, name, target, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = im.get_monitor(MonitorName=name)["Status"]
        if status == target:
            return status
        time.sleep(2.0)
    return status


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
    """UpdateMonitor(Status=INACTIVE) then Status=ACTIVE drives GetMonitor.Status through both transitions."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-toggle-")
    im.create_monitor(
        MonitorName=name, TrafficPercentageToMonitor=100, Tags={"sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    status = _wait_for_status(im, name, "ACTIVE")
    assert status == "ACTIVE", f"monitor never became ACTIVE, status={status}"

    updated = im.update_monitor(MonitorName=name, Status="INACTIVE")
    assert updated["Status"] != "ERROR", f"UpdateMonitor(INACTIVE) returned ERROR: {updated}"
    status = _wait_for_status(im, name, "INACTIVE")
    assert status == "INACTIVE", f"monitor never became INACTIVE, status={status}"

    updated = im.update_monitor(MonitorName=name, Status="ACTIVE")
    assert updated["Status"] != "ERROR", f"UpdateMonitor(ACTIVE) returned ERROR: {updated}"
    status = _wait_for_status(im, name, "ACTIVE")
    assert status == "ACTIVE", f"monitor never returned to ACTIVE, status={status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
