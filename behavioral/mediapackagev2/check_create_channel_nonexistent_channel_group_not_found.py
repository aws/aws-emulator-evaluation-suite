"""create-channel-nonexistent-channel-group-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-nonexistent-channel-group-not-found"
GROUP = "error-semantics"
SERVICES = ["mediapackagev2"]

_CHANNEL_GROUP_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel group. "
    "Verify your channel group name or add a channel group and then try again"
)


def _error(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel in a ChannelGroupName that does not exist fails ResourceNotFoundException with the
    exact message and creates nothing (GetChannel fails with the same message), while the same call in a
    real channel group succeeds."""
    mp = ctx.client("mediapackagev2")
    missing_group = ctx.unique_name("sim2real-mpv2-missing-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")

    err = _error(lambda: mp.create_channel(ChannelGroupName=missing_group, ChannelName=channel_name))
    assert err is not None, "expected CreateChannel against a missing channel group to fail, it succeeded"
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {err['Code']}"
    )
    assert err["Message"] == _CHANNEL_GROUP_NOT_FOUND, f"got {err!r}"

    # Effect absent: no channel was created under the (nonexistent) group.
    err2 = _error(lambda: mp.get_channel(ChannelGroupName=missing_group, ChannelName=channel_name))
    assert err2 is not None, "expected GetChannel against the missing group to fail, it succeeded"
    assert err2["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {err2['Code']}"
    )
    assert err2["Message"] == _CHANNEL_GROUP_NOT_FOUND, f"got {err2!r}"

    # Positive control: creating the group first makes the same CreateChannel call succeed.
    real_group = ctx.unique_name("sim2real-mpv2-grp-")
    mp.create_channel_group(ChannelGroupName=real_group, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=real_group))
    mp.create_channel(
        ChannelGroupName=real_group, ChannelName=channel_name, Tags={"purpose": "behavioral"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=real_group, ChannelName=channel_name))
    ok = mp.get_channel(ChannelGroupName=real_group, ChannelName=channel_name)
    assert ok["ChannelName"] == channel_name, (
        f"expected GetChannel to reflect ChannelName={channel_name!r}, got {ok.get('ChannelName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
