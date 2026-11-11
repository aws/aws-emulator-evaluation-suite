"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested key, leaving the other tags intact."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    created = cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"keep-me": "yes", "drop-me": "yes"},
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    arn = created["arn"]

    before = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert before == {
        "keep-me": "yes",
        "drop-me": "yes",
    }, f"expected both tags present before untag, got {before}"

    cgp.untag_resource(resourceArn=arn, tagKeys=["drop-me"])

    tags = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"keep-me": "yes"}, f"expected only keep-me to remain, got {tags}"
    assert "drop-me" not in tags, f"drop-me should have been removed, got {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
