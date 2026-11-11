"""tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-round-trip"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource's tags show up verbatim in both ListTagsForResource and
    DescribeProfilingGroup.profilingGroup.tags."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    created = cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    arn = created["arn"]

    assert created.get("tags", {}) == {}, (
        f"expected no tags on a freshly created profiling group, got {created.get('tags')!r}"
    )

    cgp.tag_resource(resourceArn=arn, tags={"team": "sim2real", "env": "test"})

    tags = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"team": "sim2real", "env": "test"}, (
        f"expected ListTagsForResource to reflect the tagged pair, got {tags!r}"
    )

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["tags"] == {"team": "sim2real", "env": "test"}, (
        f"expected DescribeProfilingGroup.tags to agree with ListTagsForResource, got {described['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
