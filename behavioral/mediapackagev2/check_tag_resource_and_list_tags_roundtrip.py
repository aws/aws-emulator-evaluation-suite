"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource are reflected by ListTagsForResource for a MediaPackage v2 resource."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")

    created = mp.create_channel_group(ChannelGroupName=group_name)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    group_arn = created["Arn"]

    mp.tag_resource(ResourceArn=group_arn, Tags={"sim2real-k1": "v1", "sim2real-k2": "v2"})

    tags_after_put = mp.list_tags_for_resource(ResourceArn=group_arn)["Tags"]
    assert tags_after_put.get("sim2real-k1") == "v1", f"expected sim2real-k1=v1, got {tags_after_put}"
    assert tags_after_put.get("sim2real-k2") == "v2", f"expected sim2real-k2=v2, got {tags_after_put}"

    mp.untag_resource(ResourceArn=group_arn, TagKeys=["sim2real-k1"])

    tags_after_untag = mp.list_tags_for_resource(ResourceArn=group_arn)["Tags"]
    assert "sim2real-k1" not in tags_after_untag, f"untagged key still present: {tags_after_untag}"
    assert tags_after_untag.get("sim2real-k2") == "v2", (
        f"unrelated tag was dropped by untag: {tags_after_untag}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
