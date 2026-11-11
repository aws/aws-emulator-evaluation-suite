"""configure-agent-updates-orchestration-timestamp."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "configure-agent-updates-orchestration-timestamp"
GROUP = "state-machine"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling ConfigureAgent for a profiling group updates that group's
    profilingStatus.latestAgentOrchestratedAt, observable via DescribeProfilingGroup, to a
    timestamp bound to the moment of the call rather than an arbitrary or stale value."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=str(uuid.uuid4()),
        agentOrchestrationConfig={"profilingEnabled": True},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    initial = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    initial_status = initial.get("profilingStatus", {}) or {}
    assert "latestAgentOrchestratedAt" not in initial_status, (
        f"expected no latestAgentOrchestratedAt before any ConfigureAgent call, got {initial_status!r}"
    )

    call_time = datetime.now(timezone.utc)
    cgp.configure_agent(profilingGroupName=name, fleetInstanceId="sim2real-fleet-instance-1")

    deadline = time.monotonic() + 30
    seen = None
    while time.monotonic() < deadline:
        status = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"].get(
            "profilingStatus", {}
        ) or {}
        seen = status.get("latestAgentOrchestratedAt")
        if seen is not None:
            break
        time.sleep(1.5)

    assert seen is not None, "latestAgentOrchestratedAt was never set after ConfigureAgent"
    assert seen >= call_time - timedelta(seconds=5), (
        f"latestAgentOrchestratedAt {seen!r} predates the ConfigureAgent call at {call_time!r} "
        "by more than clock-skew tolerance"
    )
    now = datetime.now(timezone.utc)
    assert seen <= now + timedelta(seconds=5), (
        f"latestAgentOrchestratedAt {seen!r} is ahead of the observing clock {now!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
