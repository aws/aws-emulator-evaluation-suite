"""create-profiling-group-lambda-compute-platform-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profiling-group-lambda-compute-platform-reflected"
GROUP = "lifecycle"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """computePlatform=AWSLambda supplied at creation is persisted and returned verbatim by
    both the create response and a subsequent describe (distinct from the Default platform)."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    created = cgp.create_profiling_group(
        profilingGroupName=name,
        computePlatform="AWSLambda",
        agentOrchestrationConfig={"profilingEnabled": True},
    )["profilingGroup"]
    assert created["computePlatform"] == "AWSLambda", (
        f"expected create response computePlatform=AWSLambda, got {created.get('computePlatform')!r}"
    )

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["computePlatform"] == "AWSLambda", (
        f"expected describe computePlatform=AWSLambda (not coerced to Default), "
        f"got {described.get('computePlatform')!r}"
    )
    assert described["name"] == name, f"expected describe name={name!r}, got {described.get('name')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
