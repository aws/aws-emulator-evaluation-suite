"""tag-propagates-to-list-tags-and-describe-channel."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-propagates-to-list-tags-and-describe-channel"
GROUP = 'tagging'
SERVICES = ['mediatailor']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag added via TagResource shows up in both ListTagsForResource and DescribeChannel's
    own Tags field, and UntagResource removes it from both reads the same way."""
    mt = ctx.client("mediatailor")
    name = ctx.unique_name("sim2real-behav-mt-ch-")

    created = mt.create_channel(
        ChannelName=name,
        Outputs=[{"ManifestName": "default", "SourceGroup": "default",
                  "HlsPlaylistSettings": {"ManifestWindowSeconds": 30}}],
        PlaybackMode="LOOP",
    )
    arn = created["Arn"]
    ctx.on_cleanup(_teardown(lambda: mt.delete_channel(ChannelName=name)))

    before = mt.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert before == {}, f"expected no tags before TagResource, got {before!r}"
    before_describe = mt.describe_channel(ChannelName=name)["Tags"]
    assert before_describe == {}, f"expected DescribeChannel.Tags empty before tag, got {before_describe!r}"

    mt.tag_resource(ResourceArn=arn, Tags={"sim2real-behav": "tag-propagation"})

    after_list = mt.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_list == {"sim2real-behav": "tag-propagation"}, (
        f"ListTagsForResource did not reflect the new tag, got {after_list!r}"
    )
    after_describe = mt.describe_channel(ChannelName=name)["Tags"]
    assert after_describe == {"sim2real-behav": "tag-propagation"}, (
        f"DescribeChannel.Tags did not reflect the new tag, got {after_describe!r}"
    )

    mt.untag_resource(ResourceArn=arn, TagKeys=["sim2real-behav"])

    final_list = mt.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert final_list == {}, f"ListTagsForResource still shows tags after untag: {final_list!r}"
    final_describe = mt.describe_channel(ChannelName=name)["Tags"]
    assert final_describe == {}, f"DescribeChannel.Tags still shows tags after untag: {final_describe!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
