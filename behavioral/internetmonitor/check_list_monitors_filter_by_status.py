"""list-monitors-filter-by-status."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-monitors-filter-by-status"
GROUP = "config"
SERVICES = ["internetmonitor"]


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
    """ListMonitors(MonitorStatus=ACTIVE) includes an active monitor; MonitorStatus=ERROR excludes it."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-list-")
    im.create_monitor(MonitorName=name, TrafficPercentageToMonitor=100, Tags={"env": "sim2real"})
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))
    _wait_active(im, name)

    active_names = set()
    token = None
    while True:
        kwargs = {"MonitorStatus": "ACTIVE"}
        if token:
            kwargs["NextToken"] = token
        page = im.list_monitors(**kwargs)
        active_names.update(m["MonitorName"] for m in page.get("Monitors", []))
        token = page.get("NextToken")
        if not token:
            break
    assert name in active_names, f"expected {name} in ACTIVE-filtered list, got {active_names}"

    error_names = set()
    token = None
    while True:
        kwargs = {"MonitorStatus": "ERROR"}
        if token:
            kwargs["NextToken"] = token
        page = im.list_monitors(**kwargs)
        error_names.update(m["MonitorName"] for m in page.get("Monitors", []))
        token = page.get("NextToken")
        if not token:
            break
    assert name not in error_names, f"expected {name} absent from ERROR-filtered list, got {error_names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
