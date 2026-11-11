"""create-monitor-duplicate-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-monitor-duplicate-name-rejected"
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
    """CreateMonitor with a MonitorName that already exists is rejected with ConflictException, the
    original monitor's config is left untouched, and creating a monitor under a fresh unique name
    still succeeds (positive control), confirmed by an independent read at the destination."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-dup-")
    first = im.create_monitor(
        MonitorName=name, TrafficPercentageToMonitor=15, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))
    _wait_active(im, name)

    code, message = _error(lambda: im.create_monitor(MonitorName=name, TrafficPercentageToMonitor=90))
    assert code == "ConflictException", f"expected ConflictException for duplicate name, got {code!r}"
    expected = f"Monitor with name {name} already exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = im.get_monitor(MonitorName=name)
    assert unchanged["MonitorArn"] == first["Arn"], (
        f"duplicate-create attempt changed the original monitor's Arn: "
        f"expected {first['Arn']!r}, got {unchanged['MonitorArn']!r}"
    )
    assert unchanged["TrafficPercentageToMonitor"] == 15, (
        f"duplicate-create attempt changed TrafficPercentageToMonitor: "
        f"expected 15 (original), got {unchanged['TrafficPercentageToMonitor']!r}"
    )

    other_name = ctx.unique_name("sim2real-im-dup-ctrl-")
    other_first = im.create_monitor(
        MonitorName=other_name, TrafficPercentageToMonitor=100, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, other_name))
    _wait_active(im, other_name)

    other_confirmed = im.get_monitor(MonitorName=other_name)
    assert other_confirmed["MonitorArn"] == other_first["Arn"], (
        f"fresh-name control monitor's independent read disagrees with its create response: "
        f"expected {other_first['Arn']!r}, got {other_confirmed['MonitorArn']!r}"
    )
    assert other_confirmed["TrafficPercentageToMonitor"] == 100, (
        f"fresh-name control monitor should report the TrafficPercentageToMonitor it was created "
        f"with: expected 100, got {other_confirmed['TrafficPercentageToMonitor']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
