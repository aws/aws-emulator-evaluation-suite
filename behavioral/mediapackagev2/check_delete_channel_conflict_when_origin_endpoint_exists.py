"""delete-channel-conflict-when-origin-endpoint-exists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-channel-conflict-when-origin-endpoint-exists"
GROUP = "state"
SERVICES = ["mediapackagev2"]

_CHANNEL_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel. "
    "Verify your channel name or add a channel and then try again"
)
_ORIGIN_ENDPOINT_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your origin endpoint. "
    "Verify your origin endpoint name or add an origin endpoint and then try again"
)


def _client_error(fn):
    """Call fn(); return the ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected the call to be refused but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChannel on a Channel that still has an OriginEndpoint attached is rejected
    with ConflictException(RESOURCE_IN_USE), both resources remain, and deleting the channel
    after removing the origin endpoint succeeds (positive control)."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    endpoint = ctx.unique_name("sim2real-mpkg-oe-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(ChannelGroupName=group, ChannelName=channel, Tags={"sim2real": CHECK})
    mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real": CHECK},
    )

    err = _client_error(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))
    assert err.response["Error"]["Code"] == "ConflictException", (
        f"expected ConflictException deleting a Channel with an attached OriginEndpoint, got "
        f"{err.response['Error']['Code']!r}: {err.response!r}"
    )
    expected_message = (
        "The channel you tried to delete has origin endpoints attached to it. If you want to "
        "delete this channel, you must first delete the origin endpoints attached to it"
    )
    assert err.response["Error"]["Message"] == expected_message, err.response
    assert err.response.get("ConflictExceptionType") == "RESOURCE_IN_USE", (
        f"expected ConflictExceptionType=RESOURCE_IN_USE, got "
        f"{err.response.get('ConflictExceptionType')!r}: {err.response!r}"
    )

    # Effect absent: channel and origin endpoint both still exist.
    still_channel = mp.get_channel(ChannelGroupName=group, ChannelName=channel)
    assert still_channel["ChannelName"] == channel, (
        f"expected the channel {channel!r} to survive the rejected delete, got {still_channel!r}"
    )
    still_endpoint = mp.get_origin_endpoint(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )
    assert still_endpoint["OriginEndpointName"] == endpoint, (
        f"expected the origin endpoint {endpoint!r} to survive the rejected delete, got "
        f"{still_endpoint!r}"
    )

    # Positive control: remove the origin endpoint, then the channel delete succeeds.
    mp.delete_origin_endpoint(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )
    endpoint_gone = _client_error(
        lambda: mp.get_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )
    assert endpoint_gone.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"expected the deleted origin endpoint to read back ResourceNotFoundException, got "
        f"{endpoint_gone.response['Error']['Code']!r}: {endpoint_gone.response!r}"
    )
    assert endpoint_gone.response["Error"]["Message"] == _ORIGIN_ENDPOINT_NOT_FOUND, endpoint_gone.response

    mp.delete_channel(ChannelGroupName=group, ChannelName=channel)

    channel_gone = _client_error(
        lambda: mp.get_channel(ChannelGroupName=group, ChannelName=channel)
    )
    assert channel_gone.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"expected the deleted channel to read back ResourceNotFoundException, got "
        f"{channel_gone.response['Error']['Code']!r}: {channel_gone.response!r}"
    )
    assert channel_gone.response["Error"]["Message"] == _CHANNEL_NOT_FOUND, channel_gone.response


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
