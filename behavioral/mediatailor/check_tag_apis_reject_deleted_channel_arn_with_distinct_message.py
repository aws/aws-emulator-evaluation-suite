"""tag-apis-reject-deleted-channel-arn-with-distinct-message."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-apis-reject-deleted-channel-arn-with-distinct-message"
GROUP = 'tagging'
SERVICES = ['mediatailor']


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once a channel is deleted, the generic tagging API (TagResource/ListTagsForResource/
    UntagResource) refuses its ARN with a distinct NotFoundException message from the one the
    channel-specific operations use for the same gone resource."""
    mt = ctx.client("mediatailor")
    name = ctx.unique_name("sim2real-behav-mt-ch-")
    arn = f"arn:aws:mediatailor:{ctx.region}:{ctx.account}:channel/{name}"

    mt.create_channel(
        ChannelName=name,
        Outputs=[{"ManifestName": "default", "SourceGroup": "default",
                  "HlsPlaylistSettings": {"ManifestWindowSeconds": 30}}],
        PlaybackMode="LOOP",
    )
    mt.delete_channel(ChannelName=name)

    code, message = _error(lambda: mt.list_tags_for_resource(ResourceArn=arn))
    assert code == "NotFoundException", f"ListTagsForResource on deleted arn gave {code}: {message!r}"
    assert message == "Resource was not found", f"unexpected message {message!r}"

    code, message = _error(lambda: mt.tag_resource(ResourceArn=arn, Tags={"k": "v"}))
    assert code == "NotFoundException", f"TagResource on deleted arn gave {code}: {message!r}"
    assert message == "Resource was not found", f"unexpected message {message!r}"

    code, message = _error(lambda: mt.untag_resource(ResourceArn=arn, TagKeys=["k"]))
    assert code == "NotFoundException", f"UntagResource on deleted arn gave {code}: {message!r}"
    assert message == "Resource was not found", f"unexpected message {message!r}"

    # The channel-specific surface names the same gone resource with a different message.
    code, message = _error(lambda: mt.get_channel_schedule(ChannelName=name))
    assert code == "NotFoundException", f"GetChannelSchedule on deleted channel gave {code}: {message!r}"
    assert message == "The specified channel doesn't exist.", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
