"""create-monitor-reaches-active."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-monitor-reaches-active"
GROUP = "state"
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
    """CreateMonitor starts a monitor in PENDING/ACTIVE and GetMonitor converges to Status=ACTIVE."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-mon-")
    created = im.create_monitor(
        MonitorName=name, TrafficPercentageToMonitor=100, Tags={"sim2real": "true"}
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    assert created["Status"] in ("PENDING", "ACTIVE"), (
        f"unexpected status on create: {created['Status']!r}"
    )
    assert created["Arn"].startswith("arn:"), f"malformed monitor arn: {created['Arn']!r}"

    final_status = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        got = im.get_monitor(MonitorName=name)
        final_status = got["Status"]
        if final_status == "ACTIVE":
            break
        time.sleep(2.0)

    assert final_status == "ACTIVE", f"monitor never reached ACTIVE, last status={final_status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
