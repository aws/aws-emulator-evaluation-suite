"""create-monitor-initial-state-pending."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-monitor-initial-state-pending"
GROUP = "state"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMonitor with zero probes synchronously returns state=INACTIVE (there is nothing to
    activate without a probe), and GetMonitor immediately reflects that same state — no
    eventual-only visibility of a brand-new monitor.
    """
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nwm-mon-")
    resp = nm.create_monitor(monitorName=name, aggregationPeriod=60)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    assert resp["monitorName"] == name, f"expected monitorName {name!r}, got {resp['monitorName']!r}"
    assert resp["state"] == "INACTIVE", f"expected INACTIVE for a zero-probe monitor, got {resp['state']!r}"
    assert resp["monitorArn"].startswith("arn:"), f"expected an ARN, got {resp['monitorArn']!r}"

    # GetMonitor immediately after create must reflect the same state boto3 got back synchronously.
    fetched = nm.get_monitor(monitorName=name)
    assert fetched["state"] == resp["state"], (
        f"GetMonitor state {fetched['state']!r} diverges from CreateMonitor response {resp['state']!r}"
    )
    assert fetched.get("probes", []) == [], "a monitor created with no probes must list no probes"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
