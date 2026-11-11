"""delete-monitor-removes-from-list-monitors."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-monitor-removes-from-list-monitors"
GROUP = "state"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMonitor on a probe-free monitor removes it: GetMonitor eventually 404s, it drops
    out of ListMonitors, and a mutation on the dead id is also rejected.
    """
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=60)
    ctx.on_cleanup(lambda: _delete_if_present(nm, name))

    nm.delete_monitor(monitorName=name)
    expected = f"No existing monitor found for account {ctx.account} and monitorName {name}."

    final = _poll_until_error(lambda: nm.get_monitor(monitorName=name), timeout_s=120.0, interval_s=5.0)
    assert final["Code"] == "ResourceNotFoundException", (
        f"expected GetMonitor on the deleted monitor to 404, got {final['Code']!r}"
    )
    assert final["Message"] == expected, f"expected message {expected!r}, got {final['Message']!r}"

    listed = nm.list_monitors()["monitors"]
    assert not any(m["monitorName"] == name for m in listed), "deleted monitor must not appear in ListMonitors"

    update = _error(lambda: nm.update_monitor(monitorName=name, aggregationPeriod=30))
    assert update["Code"] == "ResourceNotFoundException", (
        f"expected UpdateMonitor on the deleted monitor to be rejected as not-found, got {update['Code']!r}"
    )
    assert update["Message"] == expected, f"expected message {expected!r}, got {update['Message']!r}"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until_error(fn, timeout_s=120.0, interval_s=5.0):
    """Poll fn() until it raises a ClientError and return that error; time out loudly."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]
        time.sleep(interval_s)
    raise AssertionError(f"expected the read to start failing within {timeout_s}s; last={last!r}")


def _delete_if_present(nm, monitor_name):
    from botocore.exceptions import ClientError

    try:
        nm.delete_monitor(monitorName=monitor_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
