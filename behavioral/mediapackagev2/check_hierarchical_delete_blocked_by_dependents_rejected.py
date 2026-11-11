"""hierarchical-delete-blocked-by-dependents-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hierarchical-delete-blocked-by-dependents-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]

CHANNEL_IN_USE = (
    "The channel you tried to delete has origin endpoints attached to it. If you want to delete "
    "this channel, you must first delete the origin endpoints attached to it"
)
CHANNEL_GROUP_IN_USE = (
    "The channel group you tried to delete has channels attached to it. If you want to delete "
    "this channel group, you must first delete the channels attached to it"
)
CHANNEL_GROUP_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel group. "
    "Verify your channel group name or add a channel group and then try again"
)


def _error(fn):
    """Call fn(); return its ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    """Best-effort cleanup: ignore NotFound if the check's own teardown already ran."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a Channel/ChannelGroup that still has dependents is rejected until they're removed."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: mp.delete_channel_group(ChannelGroupName=group_name)))
    mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    )
    mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: mp.delete_origin_endpoint(
                ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
            )
        )
    )

    # Channel deletion is blocked while it still has an OriginEndpoint attached.
    err = _error(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    code = err.response["Error"]["Code"]
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    message = err.response["Error"]["Message"]
    assert message == CHANNEL_IN_USE, f"expected message {CHANNEL_IN_USE!r}, got {message!r}"
    assert err.response.get("ConflictExceptionType") == "RESOURCE_IN_USE", (
        f"expected ConflictExceptionType RESOURCE_IN_USE, got {err.response.get('ConflictExceptionType')}"
    )
    # Effect absent: the channel still exists.
    still_there = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert still_there["ChannelName"] == channel_name, (
        f"expected channel {channel_name} to still exist, got {still_there}"
    )

    # ChannelGroup deletion is blocked while it still contains a Channel.
    err2 = _error(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    code2 = err2.response["Error"]["Code"]
    assert code2 == "ConflictException", f"expected ConflictException, got {code2}"
    message2 = err2.response["Error"]["Message"]
    assert message2 == CHANNEL_GROUP_IN_USE, f"expected message {CHANNEL_GROUP_IN_USE!r}, got {message2!r}"
    assert err2.response.get("ConflictExceptionType") == "RESOURCE_IN_USE", (
        f"expected ConflictExceptionType RESOURCE_IN_USE, got {err2.response.get('ConflictExceptionType')}"
    )
    still_there_group = mp.get_channel_group(ChannelGroupName=group_name)
    assert still_there_group["ChannelGroupName"] == group_name, (
        f"expected group {group_name} to still exist, got {still_there_group}"
    )

    # Positive control: remove dependents bottom-up and the deletes now succeed.
    mp.delete_origin_endpoint(ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name)
    mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    mp.delete_channel_group(ChannelGroupName=group_name)

    final_err = _error(lambda: mp.get_channel_group(ChannelGroupName=group_name))
    final_code = final_err.response["Error"]["Code"]
    assert final_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {final_code}"
    final_message = final_err.response["Error"]["Message"]
    assert final_message == CHANNEL_GROUP_NOT_FOUND, f"expected message {CHANNEL_GROUP_NOT_FOUND!r}, got {final_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
