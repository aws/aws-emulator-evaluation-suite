"""update-monitor-traffic-percentage-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-monitor-traffic-percentage-persists"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMonitor changes to TrafficPercentageToMonitor/MaxCityNetworksToMonitor persist and are read back."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-upd-")
    im.create_monitor(
        MonitorName=name,
        TrafficPercentageToMonitor=10,
        MaxCityNetworksToMonitor=100,
        Tags={"simparity-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))
    _wait_active(im, name)

    before = im.get_monitor(MonitorName=name)
    assert before["TrafficPercentageToMonitor"] == 10, (
        f"expected TrafficPercentageToMonitor=10 at creation, got {before['TrafficPercentageToMonitor']}"
    )
    assert before["MaxCityNetworksToMonitor"] == 100, (
        f"expected MaxCityNetworksToMonitor=100 at creation, got {before['MaxCityNetworksToMonitor']}"
    )

    im.update_monitor(MonitorName=name, TrafficPercentageToMonitor=77, MaxCityNetworksToMonitor=999)

    deadline = time.monotonic() + 60.0
    after = None
    while time.monotonic() < deadline:
        after = im.get_monitor(MonitorName=name)
        if after["TrafficPercentageToMonitor"] == 77 and after["MaxCityNetworksToMonitor"] == 999:
            break
        time.sleep(2.0)
    else:
        raise AssertionError(
            "UpdateMonitor never took effect within 60s: last read "
            f"TrafficPercentageToMonitor={after['TrafficPercentageToMonitor']}, "
            f"MaxCityNetworksToMonitor={after['MaxCityNetworksToMonitor']}"
        )

    assert after is not None, "GetMonitor after update returned no result"
    assert after["TrafficPercentageToMonitor"] == 77, (
        f"expected TrafficPercentageToMonitor=77 after update, got {after['TrafficPercentageToMonitor']}"
    )
    assert after["MaxCityNetworksToMonitor"] == 999, (
        f"expected MaxCityNetworksToMonitor=999 after update, got {after['MaxCityNetworksToMonitor']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
