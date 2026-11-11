"""delete-channel-group-in-use-rejected."""
from __future__ import annotations

from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "delete-channel-group-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]

CHANNEL_GROUP_IN_USE = (
    "The channel group you tried to delete has channels attached to it. If you want to delete "
    "this channel group, you must first delete the channels attached to it"
)
CHANNEL_GROUP_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel group. "
    "Verify your channel group name or add a channel group and then try again"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChannelGroup on a group that still contains a Channel is rejected with
    ConflictException(RESOURCE_IN_USE), and the group still exists afterward; deleting
    the Channel first and retrying succeeds (positive control)."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-inuse-")
    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": "behavioral"})

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )

    err = _client_error(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    assert err is not None, "expected DeleteChannelGroup to fail while it still has a Channel"
    code = err.response["Error"]["Code"]
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    message = err.response["Error"]["Message"]
    assert message == CHANNEL_GROUP_IN_USE, f"expected message {CHANNEL_GROUP_IN_USE!r}, got {message!r}"
    conflict_type = err.response.get("ConflictExceptionType")
    assert conflict_type == "RESOURCE_IN_USE", (
        f"expected ConflictExceptionType RESOURCE_IN_USE, got {conflict_type}"
    )

    # effect absent: the group still exists
    mp.get_channel_group(ChannelGroupName=group_name)

    # positive control: delete the channel, then the group deletion succeeds
    mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    mp.delete_channel_group(ChannelGroupName=group_name)

    err2 = _client_error(lambda: mp.get_channel_group(ChannelGroupName=group_name))
    assert err2 is not None, "expected the group to be gone after a clean delete"
    code2 = err2.response["Error"]["Code"]
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    message2 = err2.response["Error"]["Message"]
    assert message2 == CHANNEL_GROUP_NOT_FOUND, f"expected message {CHANNEL_GROUP_NOT_FOUND!r}, got {message2!r}"


def _client_error(fn: Callable[[], Any]) -> Optional[Any]:
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
