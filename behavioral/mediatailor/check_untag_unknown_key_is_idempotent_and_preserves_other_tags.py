"""untag-unknown-key-is-idempotent-and-preserves-other-tags."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-unknown-key-is-idempotent-and-preserves-other-tags"
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
    """UntagResource on a tag key that was never set succeeds without error and leaves
    every other tag on the resource untouched."""
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

    mt.tag_resource(ResourceArn=arn, Tags={"keep-a": "1", "keep-b": "2"})

    # TagKeys names a key that was never set; AWS must treat this as a no-op, not an error.
    mt.untag_resource(ResourceArn=arn, TagKeys=["never-set"])

    tags_after = mt.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after == {"keep-a": "1", "keep-b": "2"}, (
        f"untagging an unknown key disturbed existing tags, got {tags_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
