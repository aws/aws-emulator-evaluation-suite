"""list-channels-reflects-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-channels-reflects-lifecycle"
GROUP = "state"
SERVICES = ["mediapackagev2"]


CHANNEL_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel. "
    "Verify your channel name or add a channel and then try again"
)


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected a ClientError, call succeeded instead: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannels includes every Channel created under a ChannelGroup and stops
    including one as soon as it's deleted."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_a = ctx.unique_name("sim2real-mpv2-ch-a-")
    channel_b = ctx.unique_name("sim2real-mpv2-ch-b-")
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_a, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_a))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_b, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_b))

    names = {c["ChannelName"] for c in mp.list_channels(ChannelGroupName=group_name)["Items"]}
    assert channel_a in names, f"{channel_a} missing from ListChannels: {names}"
    assert channel_b in names, f"{channel_b} missing from ListChannels: {names}"

    mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_b)
    names_after = {
        c["ChannelName"] for c in mp.list_channels(ChannelGroupName=group_name)["Items"]
    }
    assert channel_a in names_after, f"{channel_a} unexpectedly disappeared: {names_after}"
    assert channel_b not in names_after, f"{channel_b} still listed after delete: {names_after}"

    get_err = _client_error(
        lambda: mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_b)
    )
    get_code = get_err.response["Error"]["Code"]
    assert get_code == "ResourceNotFoundException", (
        f"GetChannel on deleted {channel_b} returned {get_code}, want ResourceNotFoundException"
    )
    get_message = get_err.response["Error"]["Message"]
    assert get_message == CHANNEL_NOT_FOUND, f"expected message {CHANNEL_NOT_FOUND!r}, got {get_message!r}"

    update_err = _client_error(
        lambda: mp.update_channel(
            ChannelGroupName=group_name, ChannelName=channel_b, Description="post-delete"
        )
    )
    update_code = update_err.response["Error"]["Code"]
    assert update_code == "ResourceNotFoundException", (
        f"UpdateChannel on deleted {channel_b} returned {update_code}, want ResourceNotFoundException"
    )
    update_message = update_err.response["Error"]["Message"]
    assert update_message == CHANNEL_NOT_FOUND, f"expected message {CHANNEL_NOT_FOUND!r}, got {update_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
