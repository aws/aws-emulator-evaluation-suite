"""tag-and-list-tags-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "tag-and-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges new tags into a profiling group's tag map and UntagResource removes
    specific keys, both observable via ListTagsForResource."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    created = cgp.create_profiling_group(
        profilingGroupName=name, clientToken=str(uuid.uuid4()), tags={"team": "perf"}
    )["profilingGroup"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    at_creation = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert at_creation == {"team": "perf"}, f"expected tags at creation {{'team': 'perf'}}, got {at_creation}"

    cgp.tag_resource(resourceArn=arn, tags={"stage": "dev"})
    after_tag = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after_tag == {
        "team": "perf",
        "stage": "dev",
    }, f"expected TagResource to merge into existing tags, got {after_tag}"

    cgp.untag_resource(resourceArn=arn, tagKeys=["team"])
    after_untag = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after_untag == {"stage": "dev"}, f"expected UntagResource to remove only 'team', got {after_untag}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
