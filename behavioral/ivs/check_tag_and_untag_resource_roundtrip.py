"""tag-and-untag-resource-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-roundtrip"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource round-trip through ListTagsForResource: a tag
    applied after creation is visible on a subsequent read, and removing it makes
    it disappear -- without disturbing an unrelated tag."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-tag-")
    channel = ivs.create_channel(name=name, tags={"Keep": "always"})["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel["arn"]))

    initial_tags = ivs.list_tags_for_resource(resourceArn=channel["arn"])["tags"]
    assert initial_tags == {"Keep": "always"}, (
        f"expected only the creation-time tag {{'Keep': 'always'}}, got {initial_tags}"
    )

    ivs.tag_resource(resourceArn=channel["arn"], tags={"Env": "sim2real-test"})
    after_tag = ivs.list_tags_for_resource(resourceArn=channel["arn"])["tags"]
    assert after_tag == {"Keep": "always", "Env": "sim2real-test"}, (
        f"expected TagResource to add 'Env' without disturbing 'Keep', got {after_tag}"
    )

    ivs.untag_resource(resourceArn=channel["arn"], tagKeys=["Env"])
    after_untag = ivs.list_tags_for_resource(resourceArn=channel["arn"])["tags"]
    assert after_untag == {"Keep": "always"}, (
        f"expected UntagResource to remove 'Env' and leave only 'Keep', got {after_untag}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
