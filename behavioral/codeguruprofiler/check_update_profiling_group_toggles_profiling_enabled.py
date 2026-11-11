"""update-profiling-group-toggles-profiling-enabled."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-profiling-group-toggles-profiling-enabled"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProfilingGroup flips agentOrchestrationConfig.profilingEnabled and
    DescribeProfilingGroup reflects each transition (true -> false -> true)."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    actual = described["agentOrchestrationConfig"]["profilingEnabled"]
    assert actual is True, f"expected profilingEnabled=True at creation, got {actual!r}"

    updated = cgp.update_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": False},
    )["profilingGroup"]
    actual = updated["agentOrchestrationConfig"]["profilingEnabled"]
    assert actual is False, f"expected UpdateProfilingGroup response profilingEnabled=False, got {actual!r}"
    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    actual = described["agentOrchestrationConfig"]["profilingEnabled"]
    assert actual is False, f"expected DescribeProfilingGroup to reflect profilingEnabled=False, got {actual!r}"

    updated = cgp.update_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )["profilingGroup"]
    actual = updated["agentOrchestrationConfig"]["profilingEnabled"]
    assert actual is True, f"expected UpdateProfilingGroup response profilingEnabled=True, got {actual!r}"
    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    actual = described["agentOrchestrationConfig"]["profilingEnabled"]
    assert actual is True, f"expected DescribeProfilingGroup to reflect profilingEnabled=True, got {actual!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
