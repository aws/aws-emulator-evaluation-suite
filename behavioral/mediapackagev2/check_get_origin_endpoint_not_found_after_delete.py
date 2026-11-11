"""get-origin-endpoint-not-found-after-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-origin-endpoint-not-found-after-delete"
GROUP = "error-semantics"
SERVICES = ["mediapackagev2"]


ORIGIN_ENDPOINT_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your origin endpoint. "
    "Verify your origin endpoint name or add an origin endpoint and then try again"
)


def _client_error(fn):
    """Call fn(); return the ClientError it raises. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteOriginEndpoint, GetOriginEndpoint fails ResourceNotFoundException with the exact message
    and ListOriginEndpoints omits it; a second delete succeeds without bringing it back, and the parent
    channel stays describable."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    endpoint = ctx.unique_name("sim2real-mpkg-oe-")
    check_tags = {"sim2real-check": CHECK}
    mp.create_channel_group(ChannelGroupName=group, Tags=check_tags)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(ChannelGroupName=group, ChannelName=channel, Tags=check_tags)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))
    mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags=check_tags,
    )

    mp.delete_origin_endpoint(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )

    err = _client_error(
        lambda: mp.get_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )
    code = err.response["Error"]["Code"]
    assert code == "ResourceNotFoundException", (
        f"GetOriginEndpoint on a deleted endpoint: expected ResourceNotFoundException, got {code}"
    )
    message = err.response["Error"]["Message"]
    assert message == ORIGIN_ENDPOINT_NOT_FOUND, f"expected message {ORIGIN_ENDPOINT_NOT_FOUND!r}, got {message!r}"

    remaining = mp.list_origin_endpoints(ChannelGroupName=group, ChannelName=channel)["Items"]
    remaining_names = {item["OriginEndpointName"] for item in remaining}
    assert endpoint not in remaining_names, (
        f"deleted endpoint {endpoint} still listed by ListOriginEndpoints: {remaining_names}"
    )

    # DeleteOriginEndpoint is idempotent on a dead id: the second call is a no-op
    # success, so the independent read right after proves it does not resurrect the endpoint.
    mp.delete_origin_endpoint(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )
    remaining_after_double_delete = mp.list_origin_endpoints(
        ChannelGroupName=group, ChannelName=channel
    )["Items"]
    remaining_after_double_delete_names = {
        item["OriginEndpointName"] for item in remaining_after_double_delete
    }
    assert endpoint not in remaining_after_double_delete_names, (
        f"double DeleteOriginEndpoint resurrected {endpoint}: {remaining_after_double_delete_names}"
    )

    # Positive control: the parent channel is unaffected.
    got_channel = mp.get_channel(ChannelGroupName=group, ChannelName=channel)
    assert got_channel["ChannelName"] == channel, (
        f"parent channel {channel} unexpectedly affected: {got_channel.get('ChannelName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
