"""create-describe-profiling-group-basic."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-describe-profiling-group-basic"
GROUP = "control-plane"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfilingGroup persists compute platform, orchestration config and tags,
    and DescribeProfilingGroup reflects the same values back."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    token = str(uuid.uuid4())

    created = cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=token,
        computePlatform="Default",
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real-test"},
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"
    assert created["computePlatform"] == "Default", (
        f"expected computePlatform 'Default', got {created['computePlatform']!r}"
    )
    assert created["agentOrchestrationConfig"]["profilingEnabled"] is True, (
        "expected profilingEnabled True on create response, got "
        f"{created['agentOrchestrationConfig']['profilingEnabled']!r}"
    )
    assert name in created["arn"], f"expected name {name!r} in arn, got {created['arn']!r}"

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["name"] == name, f"expected described name {name!r}, got {described['name']!r}"
    assert described["arn"] == created["arn"], (
        f"expected describe arn to match create arn {created['arn']!r}, got {described['arn']!r}"
    )
    assert described["computePlatform"] == "Default", (
        f"expected described computePlatform 'Default', got {described['computePlatform']!r}"
    )
    assert described["agentOrchestrationConfig"]["profilingEnabled"] is True, (
        "expected profilingEnabled True on describe response, got "
        f"{described['agentOrchestrationConfig']['profilingEnabled']!r}"
    )
    assert described["tags"] == {"env": "sim2real-test"}, (
        f"expected tags {{'env': 'sim2real-test'}}, got {described['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
