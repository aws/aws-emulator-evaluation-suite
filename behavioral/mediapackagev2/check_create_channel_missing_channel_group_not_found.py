"""create-channel-missing-channel-group-not-found."""
from __future__ import annotations

from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "create-channel-missing-channel-group-not-found"
GROUP = "error-semantics"
SERVICES = ["mediapackagev2"]

_CHANNEL_GROUP_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel group. "
    "Verify your channel group name or add a channel group and then try again"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel against a non-existent ChannelGroupName fails with
    ResourceNotFoundException(ResourceTypeNotFound=CHANNEL_GROUP); a real ChannelGroup
    accepts the identical CreateChannel call."""
    mp = ctx.client("mediapackagev2")

    missing_group = ctx.unique_name("sim2real-mpv2-missing-cg-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")

    err = _client_error(
        lambda: mp.create_channel(ChannelGroupName=missing_group, ChannelName=channel_name)
    )
    assert err is not None, "expected CreateChannel against a missing group to fail"
    code = err.response["Error"]["Code"]
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert err.response["Error"]["Message"] == _CHANNEL_GROUP_NOT_FOUND, err.response
    not_found_type = err.response.get("ResourceTypeNotFound")
    assert not_found_type == "CHANNEL_GROUP", (
        f"expected ResourceTypeNotFound=CHANNEL_GROUP, got {not_found_type!r}"
    )

    # effect absent: no channel exists under the (nonexistent) group either
    err2 = _client_error(
        lambda: mp.get_channel(ChannelGroupName=missing_group, ChannelName=channel_name)
    )
    assert err2 is not None, "expected GetChannel against a missing group to fail too"
    code2 = err2.response["Error"]["Code"]
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2!r}"
    assert err2.response["Error"]["Message"] == _CHANNEL_GROUP_NOT_FOUND, err2.response

    # positive control: the identical channel name succeeds under a real group
    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )
    resp = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert resp["ChannelName"] == channel_name, (
        f"expected ChannelName={channel_name!r}, got {resp.get('ChannelName')!r}"
    )
    assert resp["ChannelGroupName"] == group_name, (
        f"expected ChannelGroupName={group_name!r}, got {resp.get('ChannelGroupName')!r}"
    )


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
