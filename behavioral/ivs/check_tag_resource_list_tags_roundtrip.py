"""tag-resource-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags set at CreateChannel show up via ListTagsForResource; TagResource adds a
    tag without disturbing existing ones; UntagResource removes exactly the named key."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-tags-")
    arn = ivs.create_channel(
        name=name, tags={"Team": "sim2real", "Stage": "test"}
    )["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    tags1 = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags1 == {"Team": "sim2real", "Stage": "test"}, (
        f"expected creation-time tags {{'Team': 'sim2real', 'Stage': 'test'}}, got {tags1}"
    )

    ivs.tag_resource(resourceArn=arn, tags={"Extra": "1"})
    tags2 = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags2 == {"Team": "sim2real", "Stage": "test", "Extra": "1"}, (
        f"expected TagResource to add 'Extra' without disturbing existing tags, got {tags2}"
    )

    ivs.untag_resource(resourceArn=arn, tagKeys=["Team"])
    tags3 = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags3 == {"Stage": "test", "Extra": "1"}, (
        f"expected UntagResource to remove exactly 'Team', got {tags3}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
