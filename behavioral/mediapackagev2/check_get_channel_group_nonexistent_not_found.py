"""get-channel-group-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-channel-group-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["mediapackagev2"]


CHANNEL_GROUP_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel group. "
    "Verify your channel group name or add a channel group and then try again"
)


def _client_error(fn):
    """Call fn(); return its ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a lookup real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(
        f"real AWS rejects GetChannelGroup on a never-created name, but it SUCCEEDED and "
        f"returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetChannelGroup on a name that was never created is rejected with ResourceNotFoundException."""
    mp = ctx.client("mediapackagev2")
    missing_group = ctx.unique_name("sim2real-mpv2-missing-grp-")

    err = _client_error(lambda: mp.get_channel_group(ChannelGroupName=missing_group))
    code = err.response["Error"]["Code"]
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created channel group, got {code!r}"
    )
    message = err.response["Error"]["Message"]
    assert message == CHANNEL_GROUP_NOT_FOUND, f"expected message {CHANNEL_GROUP_NOT_FOUND!r}, got {message!r}"

    # Positive control: an actually-created group is found by the same call shape.
    real_group = ctx.unique_name("sim2real-mpv2-grp-")
    mp.create_channel_group(ChannelGroupName=real_group)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=real_group))
    ok = mp.get_channel_group(ChannelGroupName=real_group)
    assert ok["ChannelGroupName"] == real_group, (
        f"positive control: expected GetChannelGroup to return {real_group!r}, got "
        f"{ok.get('ChannelGroupName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
