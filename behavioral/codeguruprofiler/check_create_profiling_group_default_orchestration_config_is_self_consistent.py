"""create-profiling-group-default-orchestration-config-is-self-consistent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profiling-group-default-orchestration-config-is-self-consistent"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With agentOrchestrationConfig omitted, the boolean profilingEnabled default CreateProfilingGroup applies
    equals what DescribeProfilingGroup reports and the shouldProfile value ConfigureAgent returns.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    created = cgp.create_profiling_group(profilingGroupName=name)["profilingGroup"]
    default_enabled = created["agentOrchestrationConfig"]["profilingEnabled"]
    assert isinstance(default_enabled, bool), (
        f"expected CreateProfilingGroup's default profilingEnabled to be a bool, got {default_enabled!r}"
    )

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    described_enabled = described["agentOrchestrationConfig"]["profilingEnabled"]
    assert described_enabled == default_enabled, (
        f"expected DescribeProfilingGroup profilingEnabled {default_enabled!r} to match "
        f"the value CreateProfilingGroup reported, got {described_enabled!r}"
    )

    configuration = cgp.configure_agent(profilingGroupName=name)["configuration"]
    assert configuration["shouldProfile"] == default_enabled, (
        f"expected ConfigureAgent shouldProfile {default_enabled!r} to match the group's "
        f"default profilingEnabled, got {configuration['shouldProfile']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
