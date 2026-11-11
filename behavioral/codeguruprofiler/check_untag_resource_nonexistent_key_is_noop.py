"""untag-resource-nonexistent-key-is-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-key-is-noop"
GROUP = "tags"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a well-formed key that is not currently present on the profiling
    group succeeds as a no-op rather than erroring, and leaves the existing tags exactly as
    they were."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    arn = cgp.create_profiling_group(profilingGroupName=name, tags={"k1": "v1"})[
        "profilingGroup"
    ]["arn"]

    cgp.untag_resource(resourceArn=arn, tagKeys=["this-key-was-never-set"])

    tags = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"k1": "v1"}, (
        f"untagging an absent key must be a no-op, expected {{'k1': 'v1'}}, got {tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
