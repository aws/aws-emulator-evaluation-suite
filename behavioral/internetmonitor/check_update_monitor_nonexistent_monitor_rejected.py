"""update-monitor-nonexistent-monitor-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-monitor-nonexistent-monitor-rejected"
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
    """UpdateMonitor against a MonitorName that does not exist fails with ResourceNotFoundException, and
    creates nothing; UpdateMonitor against a real monitor in the same run still succeeds (positive control)."""
    im = ctx.client("internetmonitor")
    missing_name = ctx.unique_name("sim2real-im-missing-")

    code, message = _error(lambda: im.update_monitor(MonitorName=missing_name, Status="INACTIVE"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"No resource found for account {ctx.account} and resource monitor/{missing_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    names = [m["MonitorName"] for m in im.list_monitors().get("Monitors", [])]
    assert missing_name not in names, f"{missing_name!r} should not exist, but appeared in ListMonitors: {names!r}"

    real_name = ctx.unique_name("sim2real-im-real-")
    im.create_monitor(MonitorName=real_name, TrafficPercentageToMonitor=100, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, real_name))
    _wait_active(im, real_name)

    updated = im.update_monitor(MonitorName=real_name, Status="INACTIVE")
    assert updated["Status"] in ("INACTIVE", "PENDING", "ACTIVE"), f"unexpected status after UpdateMonitor: {updated['Status']!r}"

    deadline = time.monotonic() + 60.0
    final_status = updated["Status"]
    while time.monotonic() < deadline:
        final_status = im.get_monitor(MonitorName=real_name)["Status"]
        if final_status == "INACTIVE":
            break
        time.sleep(2.0)
    assert final_status == "INACTIVE", f"monitor never became INACTIVE, status={final_status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
