"""create-profiling-group-reflects-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profiling-group-reflects-config"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfilingGroup persists the requested name/computePlatform/profilingEnabled and
    DescribeProfilingGroup reflects exactly what was requested (not some server-chosen default)."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    created = cgp.create_profiling_group(
        profilingGroupName=name,
        computePlatform="Default",
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real"},
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"
    assert created["computePlatform"] == "Default", (
        f"expected computePlatform 'Default', got {created['computePlatform']!r}"
    )
    assert created["agentOrchestrationConfig"]["profilingEnabled"] is True, (
        "expected profilingEnabled True on create, got "
        f"{created['agentOrchestrationConfig']['profilingEnabled']!r}"
    )
    assert created["arn"].endswith(f":profilingGroup/{name}"), (
        f"expected arn to end with ':profilingGroup/{name}', got {created['arn']!r}"
    )

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["name"] == name, f"expected describe name {name!r}, got {described['name']!r}"
    assert described["arn"] == created["arn"], (
        f"expected describe arn to match create arn {created['arn']!r}, got {described['arn']!r}"
    )
    assert described["computePlatform"] == "Default", (
        f"expected describe computePlatform 'Default', got {described['computePlatform']!r}"
    )
    assert described["agentOrchestrationConfig"]["profilingEnabled"] is True, (
        "expected describe profilingEnabled True, got "
        f"{described['agentOrchestrationConfig']['profilingEnabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
