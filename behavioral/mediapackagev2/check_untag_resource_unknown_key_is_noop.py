"""untag-resource-unknown-key-is-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-unknown-key-is-noop"
GROUP = "tagging"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a TagKey that was never set on the resource is a no-op: it
    succeeds without error and leaves the resource's existing tags completely
    untouched."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    created = mp.create_channel_group(ChannelGroupName=group, Tags={"real-key": "real-value"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    arn = created["Arn"]

    before = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert before == {"real-key": "real-value"}, f"expected only the created tag, got {before}"

    mp.untag_resource(ResourceArn=arn, TagKeys=["this-key-was-never-set"])

    after = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after == {
        "real-key": "real-value"
    }, f"untagging an unset key must be a no-op, expected unchanged {{'real-key': 'real-value'}}, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
