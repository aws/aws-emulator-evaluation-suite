"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tags"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named tag key from a resource while leaving
    other tags on it intact."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    created = mp.create_channel_group(
        ChannelGroupName=group_name,
        Tags={"sim2real-keep": "keep-value", "sim2real-remove": "remove-value"},
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    arn = created["Arn"]

    before = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert before.get("sim2real-keep") == "keep-value", f"tag set at creation missing: {before}"
    assert before.get("sim2real-remove") == "remove-value", f"tag set at creation missing: {before}"

    mp.untag_resource(ResourceArn=arn, TagKeys=["sim2real-remove"])

    after = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "sim2real-remove" not in after, f"removed tag still present: {after}"
    assert after.get("sim2real-keep") == "keep-value", f"unrelated tag was dropped: {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
