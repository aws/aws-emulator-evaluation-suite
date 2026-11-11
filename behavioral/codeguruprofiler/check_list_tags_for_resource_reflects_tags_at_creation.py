"""list-tags-for-resource-reflects-tags-at-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-reflects-tags-at-creation"
GROUP = "tags"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied directly to CreateProfilingGroup are visible both through
    ListTagsForResource and through the tags field of DescribeProfilingGroup, and the two
    views agree exactly."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    created = cgp.create_profiling_group(
        profilingGroupName=name,
        tags={"env": "test", "owner": "sim2real"},
        agentOrchestrationConfig={"profilingEnabled": True},
    )["profilingGroup"]
    arn = created["arn"]
    assert created["tags"] == {"env": "test", "owner": "sim2real"}, (
        f"expected CreateProfilingGroup to echo {{'env': 'test', 'owner': 'sim2real'}}, "
        f"got {created['tags']!r}"
    )

    listed = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert listed == {"env": "test", "owner": "sim2real"}, (
        f"expected ListTagsForResource to return {{'env': 'test', 'owner': 'sim2real'}}, "
        f"got {listed!r}"
    )

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["tags"] == listed, (
        f"expected DescribeProfilingGroup.tags to match ListTagsForResource {listed!r}, "
        f"got {described['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
