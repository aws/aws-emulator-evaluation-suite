"""tag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource additions and UntagResource removals are both reflected by
    ListTagsForResource, without disturbing tags that were not touched."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    arn = ivs.create_channel(name=name)["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    initial_tags = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert initial_tags == {}, f"expected no tags on a freshly created channel, got {initial_tags}"

    ivs.tag_resource(resourceArn=arn, tags={"env": "sim2real", "team": "video"})
    tag_state = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tag_state == {"env": "sim2real", "team": "video"}, (
        f"expected exactly the two tags just applied, got {tag_state}"
    )

    ivs.untag_resource(resourceArn=arn, tagKeys=["team"])
    tags_after = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after == {"env": "sim2real"}, (
        f"expected only 'env' to remain after untagging 'team', got {tags_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
