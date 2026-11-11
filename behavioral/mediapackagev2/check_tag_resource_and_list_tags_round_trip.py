"""tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-round-trip"
GROUP = "tags"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a ChannelGroup ARN is visible both through ListTagsForResource
    and through the Tags field on GetChannelGroup."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    created = mp.create_channel_group(ChannelGroupName=group_name)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    arn = created["Arn"]

    mp.tag_resource(ResourceArn=arn, Tags={"sim2real-key": "sim2real-value"})

    listed = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert listed.get("sim2real-key") == "sim2real-value", f"tag missing from ListTagsForResource: {listed}"

    got = mp.get_channel_group(ChannelGroupName=group_name)
    assert got.get("Tags", {}).get("sim2real-key") == "sim2real-value", (
        f"tag missing from GetChannelGroup: {got.get('Tags')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
