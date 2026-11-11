"""tag-resource-roundtrip-and-untag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-roundtrip-and-untag"
GROUP = "tagging"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource persists a tag visible via ListTagsForResource, and UntagResource actually
    removes it (not just accepts the call and leaves the tag in place)."""
    mc = ctx.client("mediaconvert")
    name = ctx.unique_name("sim2real-mc-queue-")
    arn = mc.create_queue(Name=name)["Queue"]["Arn"]
    ctx.on_cleanup(lambda: mc.delete_queue(Name=name))

    mc.tag_resource(Arn=arn, Tags={"sim2real-check": "v1"})
    tags = mc.list_tags_for_resource(Arn=arn)["ResourceTags"]["Tags"]
    assert tags.get("sim2real-check") == "v1", f"expected tag value 'v1' after TagResource, got {tags.get('sim2real-check')!r}"

    mc.untag_resource(Arn=arn, TagKeys=["sim2real-check"])
    tags2 = mc.list_tags_for_resource(Arn=arn)["ResourceTags"]["Tags"]
    assert "sim2real-check" not in tags2, f"expected tag removed after UntagResource, still present in {tags2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
