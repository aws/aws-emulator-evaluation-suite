"""configure-agent-updates-latest-agent-orchestrated-at."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "configure-agent-updates-latest-agent-orchestrated-at"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ConfigureAgent call from an agent updates profilingStatus.latestAgentOrchestratedAt
    on the profiling group to a recent timestamp, moving the group out of its "never
    orchestrated" initial state."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real:managed": "true"},
    )

    baseline = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert "latestAgentOrchestratedAt" not in baseline.get("profilingStatus", {}), (
        f"expected no latestAgentOrchestratedAt on a freshly created group, got "
        f"{baseline.get('profilingStatus')!r}"
    )

    before_call = datetime.now(timezone.utc) - timedelta(minutes=1)
    cgp.configure_agent(profilingGroupName=name)

    described = _poll_until(
        lambda: cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"],
        lambda pg: "latestAgentOrchestratedAt" in pg.get("profilingStatus", {}),
        timeout_s=30.0,
        interval_s=2.0,
    )
    after_call = datetime.now(timezone.utc)
    orchestrated_at = described["profilingStatus"]["latestAgentOrchestratedAt"]
    assert before_call <= orchestrated_at <= after_call + timedelta(seconds=5), (
        f"expected latestAgentOrchestratedAt in [{before_call!r}, {after_call!r}], "
        f"got {orchestrated_at!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
