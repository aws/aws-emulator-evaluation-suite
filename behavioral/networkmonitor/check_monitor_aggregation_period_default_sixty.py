"""monitor-aggregation-period-default-sixty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "monitor-aggregation-period-default-sixty"
GROUP = "control-plane"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMonitor without an aggregationPeriod defaults to 60 seconds, per documented behavior."""
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nwm-mon-")
    created = nm.create_monitor(monitorName=name, tags={"sim2real": "monitor-aggregation-period-default-sixty"})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    assert created["aggregationPeriod"] == 60, f"expected default aggregationPeriod 60, got {created['aggregationPeriod']!r}"

    fetched = nm.get_monitor(monitorName=name)
    assert fetched["aggregationPeriod"] == 60, (
        f"expected persisted aggregationPeriod 60 on independent GetMonitor, got {fetched['aggregationPeriod']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
