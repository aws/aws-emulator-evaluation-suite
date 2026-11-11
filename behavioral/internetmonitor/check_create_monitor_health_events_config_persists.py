"""create-monitor-health-events-config-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-monitor-health-events-config-persists"
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
    """HealthEventsConfig thresholds supplied on CreateMonitor are echoed back exactly by GetMonitor
    once the monitor is active."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-health-cfg-")
    im.create_monitor(
        MonitorName=name,
        TrafficPercentageToMonitor=100,
        HealthEventsConfig={
            "AvailabilityScoreThreshold": 90.0,
            "PerformanceScoreThreshold": 80.0,
        },
        Tags={"team": "sim2real"},
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    deadline = time.monotonic() + 60.0
    got = None
    while time.monotonic() < deadline:
        got = im.get_monitor(MonitorName=name)
        if got["Status"] == "ACTIVE":
            break
        time.sleep(2.0)

    assert got is not None, "monitor never returned from GetMonitor"
    assert got["Status"] == "ACTIVE", f"expected Status=ACTIVE, got {got['Status']!r}"
    cfg = got["HealthEventsConfig"]
    assert cfg["AvailabilityScoreThreshold"] == 90.0, (
        f"expected AvailabilityScoreThreshold=90.0, got {cfg['AvailabilityScoreThreshold']!r}"
    )
    assert cfg["PerformanceScoreThreshold"] == 80.0, (
        f"expected PerformanceScoreThreshold=80.0, got {cfg['PerformanceScoreThreshold']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
