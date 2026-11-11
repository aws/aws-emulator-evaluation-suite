"""configure-agent-updates-latest-orchestrated-timestamp."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "configure-agent-updates-latest-orchestrated-timestamp"
GROUP = "data-plane"
SERVICES = ["codeguruprofiler"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s; last value={value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling ConfigureAgent (the agent's periodic orchestration ping) updates
    profilingStatus.latestAgentOrchestratedAt on the profiling group."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        tags={"env": "test", "owner": "sim2real"},
        agentOrchestrationConfig={"profilingEnabled": True},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    before = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    before_ts = before.get("profilingStatus", {}).get("latestAgentOrchestratedAt")
    assert before_ts is None, f"expected no latestAgentOrchestratedAt before any ConfigureAgent call, got {before_ts!r}"

    call_time = datetime.now(timezone.utc)
    cgp.configure_agent(profilingGroupName=name, fleetInstanceId="i-0123456789abcdef0")

    described = _poll_until(
        lambda: cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"],
        lambda g: g.get("profilingStatus", {}).get("latestAgentOrchestratedAt") is not None,
        timeout_s=60.0,
    )
    ts = described["profilingStatus"]["latestAgentOrchestratedAt"]
    assert ts is not None, "latestAgentOrchestratedAt was never set after ConfigureAgent"
    # The timestamp must reflect this ConfigureAgent call specifically, not some
    # unrelated stale value from before it (lower bound) or a bogus future value
    # (upper bound) — time is two-sided.
    now = datetime.now(timezone.utc)
    assert call_time - timedelta(seconds=5) <= ts <= now + timedelta(seconds=5), (
        f"expected latestAgentOrchestratedAt in [{call_time - timedelta(seconds=5)!r}, "
        f"{now + timedelta(seconds=5)!r}], got {ts!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
