"""list-monitors-state-filter."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-monitors-state-filter"
GROUP = "listing"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMonitors(state=X) includes a monitor currently in state X and excludes it when
    filtered on a different state value.
    """
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=30)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))

    current_state = _poll_until(
        lambda: nm.get_monitor(monitorName=name)["state"],
        lambda s: s != "PENDING",
        timeout_s=120.0,
        interval_s=5.0,
    )

    matching = nm.list_monitors(state=current_state)["monitors"]
    assert any(m["monitorName"] == name for m in matching), "monitor missing from list filtered on its own state"

    other_state = "ERROR" if current_state != "ERROR" else "INACTIVE"
    mismatched = nm.list_monitors(state=other_state)["monitors"]
    assert not any(m["monitorName"] == name for m in mismatched), "monitor should not appear under an unrelated state filter"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
