"""get-monitor-reflects-created-config."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-monitor-reflects-created-config"
GROUP = "config"
SERVICES = ["internetmonitor"]


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
    """GetMonitor echoes back the exact TrafficPercentageToMonitor/MaxCityNetworksToMonitor set at creation."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-cfg-")
    im.create_monitor(
        MonitorName=name,
        TrafficPercentageToMonitor=42,
        MaxCityNetworksToMonitor=1234,
        Tags={"sim2real-check": "get-monitor-reflects-created-config"},
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    deadline = time.monotonic() + 60.0
    got = None
    while time.monotonic() < deadline:
        got = im.get_monitor(MonitorName=name)
        if got["Status"] == "ACTIVE":
            break
        time.sleep(2.0)

    assert got is not None, "get_monitor never returned a result"
    assert got["Status"] == "ACTIVE", f"expected Status=ACTIVE, got {got['Status']!r}"
    assert got["MonitorName"] == name, f"expected MonitorName={name!r}, got {got['MonitorName']!r}"
    assert got["TrafficPercentageToMonitor"] == 42, (
        f"expected TrafficPercentageToMonitor=42, got {got['TrafficPercentageToMonitor']!r}"
    )
    assert got["MaxCityNetworksToMonitor"] == 1234, (
        f"expected MaxCityNetworksToMonitor=1234, got {got['MaxCityNetworksToMonitor']!r}"
    )
    assert got["Resources"] == [], (
        f"expected no auto-associated resources on a monitor created with no ResourcesToAdd, "
        f"got {got['Resources']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
