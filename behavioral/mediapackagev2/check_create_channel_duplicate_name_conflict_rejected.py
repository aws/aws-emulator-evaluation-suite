"""create-channel-duplicate-name-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


def _error(fn):
    """Call fn(); return its ClientError (Code and Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a Channel whose name already exists in the ChannelGroup is rejected with ConflictException."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    other_channel_name = ctx.unique_name("sim2real-mpv2-ch2-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Description="first", Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    err = _error(
        lambda: mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Description="duplicate")
    )
    assert err["Code"] == "ConflictException", f"expected ConflictException for a duplicate ChannelName, got {err!r}"
    expected_message = (
        "MediaPackage can't create the resource you requested because a resource with that "
        "name already exists. Verify the name of the resource and then try again"
    )
    assert err["Message"] == expected_message, f"got {err!r}"

    # Effect absent: the original channel's description was not overwritten by the failed duplicate attempt.
    unchanged = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert unchanged["Description"] == "first", (
        f"expected the original channel's Description to remain 'first', got {unchanged['Description']!r}"
    )

    # Positive control: creating a channel with a distinct name in the same group succeeds.
    mp.create_channel(ChannelGroupName=group_name, ChannelName=other_channel_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=other_channel_name))
    ok = mp.get_channel(ChannelGroupName=group_name, ChannelName=other_channel_name)
    assert ok["ChannelName"] == other_channel_name, (
        f"expected the differently-named channel {other_channel_name!r} to exist, got {ok.get('ChannelName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
