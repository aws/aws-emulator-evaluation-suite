"""create-monitor-traffic-percentage-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-monitor-traffic-percentage-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["internetmonitor"]


def _safe_delete_monitor(im, name, timeout_s=50.0):
    """DeleteMonitor requires the monitor be INACTIVE first; transition it, then delete.

    UpdateMonitor refuses a PENDING monitor, so the transition is retried to the deadline.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            im.update_monitor(MonitorName=name, Status="INACTIVE")
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
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


def _unvalidated_client(ctx):
    """An internetmonitor client on the ctx target with botocore's parameter validation disabled.

    TrafficPercentageToMonitor's 1-100 range lives in the model, so a validating client raises a
    local ParamValidationError for 0 before any request reaches the network. Sending the request
    unvalidated observes the service, not the SDK, enforcing the boundary.
    """
    return ctx.client("internetmonitor", config=Config(parameter_validation=False))


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CreateMonitor rejects TrafficPercentageToMonitor=0 (valid range 1-100) with a server-side
    BadRequestException "Invalid request body" and creates no monitor, while a valid percentage
    succeeds (positive control)."""
    im = ctx.client("internetmonitor")
    raw = _unvalidated_client(ctx)
    bad_name = ctx.unique_name("sim2real-im-badpct-")

    code, message = _error(
        lambda: raw.create_monitor(MonitorName=bad_name, TrafficPercentageToMonitor=0)
    )
    assert code == "BadRequestException", f"CODE={code!r}"
    assert message == "Invalid request body", f"MESSAGE={message!r}"

    names = [m["MonitorName"] for m in im.list_monitors().get("Monitors", [])]
    assert bad_name not in names, f"rejected monitor should not have been created: {names}"

    good_name = ctx.unique_name("sim2real-im-goodpct-")
    im.create_monitor(MonitorName=good_name, TrafficPercentageToMonitor=25)
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, good_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
