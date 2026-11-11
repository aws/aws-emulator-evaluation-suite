"""update-monitor-aggregation-period-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-monitor-aggregation-period-persists"
GROUP = "state"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMonitor changes aggregationPeriod from 30 to 60 in its response and on GetMonitor; after
    DeleteMonitor, GetMonitor and UpdateMonitor both fail with ResourceNotFoundException and the
    exact message."""
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=30, tags={"env": "sim2real-created"})
    ctx.on_cleanup(lambda: _delete_if_present(nm, name))

    initial = nm.get_monitor(monitorName=name)["aggregationPeriod"]
    assert initial == 30, f"expected initial aggregationPeriod 30, got {initial}"

    update_resp = nm.update_monitor(monitorName=name, aggregationPeriod=60)
    assert update_resp["aggregationPeriod"] == 60, (
        f"expected UpdateMonitor response aggregationPeriod 60, got {update_resp['aggregationPeriod']}"
    )

    get_resp = nm.get_monitor(monitorName=name)
    assert get_resp["aggregationPeriod"] == 60, (
        f"expected persisted aggregationPeriod 60, got {get_resp['aggregationPeriod']}"
    )

    nm.delete_monitor(monitorName=name)

    not_found = f"No existing monitor found for account {ctx.account} and monitorName {name}."
    final_code, final_message = _poll_until_rejected(
        lambda: nm.get_monitor(monitorName=name), timeout_s=120.0, interval_s=5.0,
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected deleted monitor GetMonitor to 404, got {final_code}"
    )
    assert final_message == not_found, f"expected message {not_found!r}, got {final_message!r}"

    mutate_code, mutate_message = _error(lambda: nm.update_monitor(monitorName=name, aggregationPeriod=60))
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateMonitor on deleted monitor to fail not-found, got {mutate_code}"
    )
    assert mutate_message == not_found, f"expected message {not_found!r}, got {mutate_message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_rejected(fn, timeout_s=120.0, interval_s=5.0):
    """Retry fn() until it is rejected, then return that (code, message); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _error(fn)
        except AssertionError as still_accepted:
            if time.monotonic() > deadline:
                raise AssertionError(f"call still accepted after {timeout_s}s: {still_accepted}") from None
        time.sleep(interval_s)


def _delete_if_present(nm, name):
    from botocore.exceptions import ClientError

    try:
        nm.delete_monitor(monitorName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
