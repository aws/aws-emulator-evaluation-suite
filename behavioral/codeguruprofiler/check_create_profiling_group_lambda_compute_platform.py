"""create-profiling-group-lambda-compute-platform."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profiling-group-lambda-compute-platform"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfilingGroup honors computePlatform=AWSLambda and it is preserved
    verbatim (not silently coerced to the Default platform) on describe."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    created = cgp.create_profiling_group(
        profilingGroupName=name,
        computePlatform="AWSLambda",
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real"},
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    assert created["computePlatform"] == "AWSLambda", (
        f"create response computePlatform: expected AWSLambda, got {created.get('computePlatform')!r}"
    )

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["computePlatform"] == "AWSLambda", (
        f"describe computePlatform: expected AWSLambda, got {described.get('computePlatform')!r}"
    )
    assert described["name"] == name, (
        f"describe name: expected {name!r}, got {described.get('name')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
